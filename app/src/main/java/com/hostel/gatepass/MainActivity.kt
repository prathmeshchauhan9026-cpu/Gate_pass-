package com.hostel.gatepass

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.util.Patterns
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import androidx.navigation.compose.*
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseException
import com.google.firebase.auth.*
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.Query
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.TimeUnit

// ============================================================================
// 1. DATA MODELS & ENUMS
// ============================================================================

enum class UserRole { STUDENT, ADVISOR, PARENT, WARDEN, ADMIN }

enum class PassStatus {
    PENDING_ADVISOR,     // Step 1: Student submitted
    REJECTED_ADVISOR,    // Advisor rejected
    PENDING_PARENT,      // Step 2: Advisor approved -> Shown on Parent dashboard
    REJECTED_PARENT,     // Parent rejected
    APPROVED_EXIT,       // Step 3: Parent verified OTP -> Advisor & Warden notified
    ENTRY_INITIATED,     // Step 4: Student initiates return entry -> Sent to Parent
    ENTRY_COMPLETED      // Step 5: Parent confirms entry -> Advisor & Warden notified
}

data class UserProfile(
    val uid: String = "",
    val role: String = UserRole.STUDENT.name,
    val fullName: String = "",
    val loginId: String = "",    // What user actually types: "shreya123" or "shreya@123"
    val email: String = "",      // Internal Firebase Auth email
    val isGmail: Boolean = false,
    val phone: String = "",      // Format: +91XXXXXXXXXX
    val rollNumber: String = "",
    val roomNumber: String = "",
    val advisorId: String = "",
    val parentPhone: String = "" // Format: +91XXXXXXXXXX
)

data class GatePass(
    val passId: String = "",
    val studentId: String = "",
    val studentName: String = "",
    val roomNumber: String = "",
    val advisorId: String = "",
    val parentPhone: String = "",
    val date: String = "",
    val destination: String = "",
    val reason: String = "",
    val outTiming: String = "",
    val expectedInTiming: String = "",
    val status: String = PassStatus.PENDING_ADVISOR.name,
    val notificationLog: List<String> = emptyList(),
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)

// ============================================================================
// 2. SMART ID ENCODER (SUPPORTS "shreya123", "shreya@123", & REAL GMAIL)
// ============================================================================

data class ResolvedAccountInput(
    val rawLoginId: String,
    val firebaseEmail: String,
    val isRealGmail: Boolean
)

object AuthValidator {
    // Allows letters, numbers, dots, underscores, hyphens, and @ inside custom IDs
    private val CUSTOM_ID_REGEX = Regex("^[a-zA-Z0-9._@-]{3,35}$")
    private val GMAIL_REGEX = Regex("^[a-zA-Z0-9._%+-]+@gmail\\.com$", RegexOption.IGNORE_CASE)
    private val INDIA_PHONE_REGEX = Regex("^\\+91[6-9][0-9]{9}$")

    fun resolveIdOrEmail(input: String, role: UserRole): Result<ResolvedAccountInput> = runCatching {
        val clean = input.trim().lowercase()
        if (clean.isEmpty()) throw Exception("ID cannot be empty.")

        // Case 1: Admin logging in with a standard email like admin@hostel.com
        if (role == UserRole.ADMIN && Patterns.EMAIL_ADDRESS.matcher(clean).matches()) {
            return@runCatching ResolvedAccountInput(
                rawLoginId = clean,
                firebaseEmail = clean,
                isRealGmail = false
            )
        }

        // Case 2: User explicitly typed a full @gmail.com address (or tried to type @gmail...)
        if (clean.endsWith("@gmail.com") || clean.contains("@gmail.")) {
            if (!Patterns.EMAIL_ADDRESS.matcher(clean).matches() || !GMAIL_REGEX.matches(clean)) {
                throw Exception("Invalid Gmail address format.")
            }
            return@runCatching ResolvedAccountInput(
                rawLoginId = clean,
                firebaseEmail = clean,
                isRealGmail = true
            )
        }

        // Case 3: Custom Short ID (e.g., "shreya123" OR "shreya@123" OR "adv@01")
        if (!CUSTOM_ID_REGEX.matches(clean)) {
            throw Exception("Invalid ID '$clean'. Use 3-35 characters (letters, numbers, @, _, .) with no spaces.")
        }

        // Replace any '@' in custom IDs like "shreya@123" with ".at." so Firebase Auth accepts it
        val safeLocalPart = clean.replace("@", ".at.")
            .trimStart('.')
            .trimEnd('.')
            .replace("..", ".")

        ResolvedAccountInput(
            rawLoginId = clean,
            firebaseEmail = "$safeLocalPart@hostel.local",
            isRealGmail = false
        )
    }

    fun normalizeAndValidatePhone(phoneInput: String): Result<String> = runCatching {
        val clean = phoneInput.replace(" ", "").trim()
        val formatted = when {
            clean.length == 10 && clean.all { it.isDigit() } -> "+91$clean"
            clean.startsWith("+91") -> clean
            else -> throw Exception("Phone number must be 10 digits or start with +91")
        }
        if (!INDIA_PHONE_REGEX.matches(formatted)) {
            throw Exception("Invalid 10-digit Indian mobile number: $formatted")
        }
        formatted
    }

    fun isPhoneInput(input: String): Boolean {
        val clean = input.replace(" ", "").trim()
        return clean.startsWith("+91") || (clean.length == 10 && clean.all { it.isDigit() })
    }
}

// ============================================================================
// 3. REPOSITORY (AUTH, SECONDARY INSTANCE, PARENT REGISTRATION, FIRESTORE)
// ============================================================================

class GatePassRepository(private val context: Context) {
    private val auth: FirebaseAuth = FirebaseAuth.getInstance()
    private val db: FirebaseFirestore = FirebaseFirestore.getInstance()

    private fun getSecondaryAuth(): FirebaseAuth {
        val options = FirebaseApp.getInstance().options
        val secondaryApp = try {
            FirebaseApp.getInstance("SecondaryCreationApp")
        } catch (e: Exception) {
            FirebaseApp.initializeApp(context, options, "SecondaryCreationApp")
        }
        return FirebaseAuth.getInstance(secondaryApp)
    }

    // Used by Admin (creates Advisor/Warden) and Advisor (creates Student with ID like "shreya123")
    suspend fun createAccountWithoutLogout(
        customIdInput: String,
        password: String,
        profile: UserProfile
    ): Result<String> = runCatching {
        if (password.length < 6) throw Exception("Password must be at least 6 characters.")
        val targetRole = UserRole.valueOf(profile.role)
        val resolved = AuthValidator.resolveIdOrEmail(customIdInput, targetRole).getOrThrow()

        val secondaryAuth = getSecondaryAuth()
        val result = secondaryAuth.createUserWithEmailAndPassword(resolved.firebaseEmail, password).await()
        val newUser = result.user ?: throw Exception("Failed to create account.")

        if (resolved.isRealGmail) {
            newUser.sendEmailVerification().await()
        }

        val finalProfile = profile.copy(
            uid = newUser.uid,
            loginId = resolved.rawLoginId,
            email = resolved.firebaseEmail,
            isGmail = resolved.isRealGmail
        )

        db.collection("users").document(newUser.uid).set(finalProfile).await()
        secondaryAuth.signOut()

        "Created ${profile.role}! Login ID: ${resolved.rawLoginId}"
    }

    // Parent Self-Registration (Can register with Gmail/ID + Phone Number)
    suspend fun registerParentAccount(
        fullName: String,
        idOrGmailInput: String,
        phoneInput: String,
        password: String
    ): Result<String> = runCatching {
        if (fullName.isBlank()) throw Exception("Parent full name is required.")
        if (password.length < 6) throw Exception("Password must be at least 6 characters.")

        val validPhone = AuthValidator.normalizeAndValidatePhone(phoneInput).getOrThrow()
        // If Parent left ID blank, use their 10-digit phone number as their ID automatically
        val effectiveIdInput = idOrGmailInput.ifBlank { validPhone.removePrefix("+91") }
        val resolved = AuthValidator.resolveIdOrEmail(effectiveIdInput, UserRole.PARENT).getOrThrow()

        val existingPhone = db.collection("users")
            .whereEqualTo("role", UserRole.PARENT.name)
            .whereEqualTo("phone", validPhone)
            .get().await()

        if (!existingPhone.isEmpty) {
            throw Exception("Mobile $validPhone is already registered. Please switch to Login.")
        }

        val res = auth.createUserWithEmailAndPassword(resolved.firebaseEmail, password).await()
        val user = res.user ?: throw Exception("Registration failed.")

        val parentProfile = UserProfile(
            uid = user.uid,
            role = UserRole.PARENT.name,
            fullName = fullName.trim(),
            loginId = resolved.rawLoginId,
            email = resolved.firebaseEmail,
            isGmail = resolved.isRealGmail,
            phone = validPhone
        )

        db.collection("users").document(user.uid).set(parentProfile).await()

        if (resolved.isRealGmail) {
            user.sendEmailVerification().await()
            auth.signOut()
            "Verification link sent to ${resolved.rawLoginId}! Click the link in your Gmail inbox, then login."
        } else {
            "Parent account created! You can now login with Phone ($validPhone) or ID (${resolved.rawLoginId})."
        }
    }

    // Universal Login for all Roles
    suspend fun loginUser(
        identifier: String,
        password: String,
        expectedRole: UserRole
    ): Result<UserProfile> = runCatching {
        val cleanInput = identifier.trim()
        if (cleanInput.isEmpty() || password.isEmpty()) {
            throw Exception("Please enter both ID and Password.")
        }

        // If Parent (or Staff) enters their Phone Number, look up their internal auth email
        val firebaseEmailToUse: String = if (AuthValidator.isPhoneInput(cleanInput)) {
            val normalizedPhone = AuthValidator.normalizeAndValidatePhone(cleanInput).getOrThrow()
            val querySnap = db.collection("users")
                .whereEqualTo("role", expectedRole.name)
                .whereEqualTo("phone", normalizedPhone)
                .get().await()

            if (querySnap.isEmpty) {
                throw Exception("No ${expectedRole.name} account registered with mobile $normalizedPhone.")
            }
            querySnap.documents.first().getString("email")
                ?: throw Exception("Account record corrupted.")
        } else {
            AuthValidator.resolveIdOrEmail(cleanInput, expectedRole).getOrThrow().firebaseEmail
        }

        val res = auth.signInWithEmailAndPassword(firebaseEmailToUse, password).await()
        val firebaseUser = res.user ?: throw Exception("Authentication failed.")

        val doc = db.collection("users").document(firebaseUser.uid).get().await()
        val profile = doc.toObject(UserProfile::class.java)
            ?: throw Exception("User profile missing in Firestore.")

        if (profile.role != expectedRole.name) {
            auth.signOut()
            throw Exception("Access Denied: This ID belongs to ${profile.role}, not ${expectedRole.name}.")
        }

        // Only check Gmail verification if they explicitly registered with a real @gmail.com
        if (profile.isGmail) {
            firebaseUser.reload().await()
            if (!firebaseUser.isEmailVerified) {
                firebaseUser.sendEmailVerification().await()
                auth.signOut()
                throw Exception("Gmail (${profile.loginId}) is unverified! Check your Gmail inbox for our verification link.")
            }
        }

        profile
    }

    // Isolated OTP check when Parent clicks "Allow Exit"
    suspend fun verifyParentOtpIsolated(verificationId: String, otpCode: String): Result<Unit> = runCatching {
        val cred = PhoneAuthProvider.getCredential(verificationId, otpCode.trim())
        val secondaryAuth = getSecondaryAuth()
        secondaryAuth.signInWithCredential(cred).await()
        secondaryAuth.signOut()
    }

    suspend fun submitGatePass(pass: GatePass): Result<Unit> = runCatching {
        val ref = db.collection("gate_passes").document()
        val initialLog = "Pass applied by ${pass.studentName} on ${formatTime(System.currentTimeMillis())}"
        val finalPass = pass.copy(
            passId = ref.id,
            status = PassStatus.PENDING_ADVISOR.name,
            notificationLog = listOf(initialLog)
        )
        ref.set(finalPass).await()
    }

    suspend fun updatePassStatus(passId: String, newStatus: PassStatus, logMessage: String): Result<Unit> = runCatching {
        val ref = db.collection("gate_passes").document(passId)
        db.runTransaction { tx ->
            val snap = tx.get(ref)
            val currentLogs = snap.get("notificationLog") as? List<String> ?: emptyList()
            val updatedLogs = currentLogs + "[${formatTime(System.currentTimeMillis())}] $logMessage"
            tx.update(ref, mapOf(
                "status" to newStatus.name,
                "notificationLog" to updatedLogs,
                "updatedAt" to System.currentTimeMillis()
            ))
        }.await()
    }

    fun streamStudentPasses(studentId: String): Flow<List<GatePass>> = streamQuery(
        db.collection("gate_passes").whereEqualTo("studentId", studentId)
    )

    fun streamAdvisorPasses(advisorId: String): Flow<List<GatePass>> = streamQuery(
        db.collection("gate_passes").whereEqualTo("advisorId", advisorId)
    )

    fun streamParentPasses(parentPhone: String): Flow<List<GatePass>> = streamQuery(
        db.collection("gate_passes").whereEqualTo("parentPhone", parentPhone.trim())
    )

    fun streamAllPassesForWarden(): Flow<List<GatePass>> = streamQuery(
        db.collection("gate_passes").orderBy("createdAt", Query.Direction.DESCENDING)
    )

    private fun streamQuery(query: Query): Flow<List<GatePass>> = callbackFlow {
        val sub = query.addSnapshotListener { snap, err ->
            if (err != null) {
                close(err)
                return@addSnapshotListener
            }
            val list = snap?.toObjects(GatePass::class.java)?.sortedByDescending { it.createdAt } ?: emptyList()
            trySend(list)
        }
        awaitClose { sub.remove() }
    }

    fun logout() = auth.signOut()
}

fun formatTime(millis: Long): String {
    return SimpleDateFormat("dd MMM, hh:mm a", Locale.getDefault()).format(Date(millis))
}

// ============================================================================
// 4. MAIN ACTIVITY & NAVIGATION
// ============================================================================

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val repo = GatePassRepository(applicationContext)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    AppNavigation(repo)
                }
            }
        }
    }
}

@Composable
fun AppNavigation(repo: GatePassRepository) {
    val navController = rememberNavController()
    var currentUser by remember { mutableStateOf<UserProfile?>(null) }

    NavHost(navController = navController, startDestination = "home") {
        composable("home") {
            HomeScreen(navController)
        }
        composable("login/{role}") { backStackEntry ->
            val roleStr = backStackEntry.arguments?.getString("role") ?: "STUDENT"
            val role = UserRole.valueOf(roleStr)
            if (role == UserRole.PARENT) {
                ParentAuthScreen(
                    repo = repo,
                    onAuthSuccess = { profile ->
                        currentUser = profile
                        navController.navigate("dashboard_parent") { popUpTo("home") }
                    },
                    onBack = { navController.popBackStack() }
                )
            } else {
                StandardLoginScreen(
                    role = role,
                    repo = repo,
                    onLoginSuccess = { profile ->
                        currentUser = profile
                        when (role) {
                            UserRole.STUDENT -> navController.navigate("dashboard_student") { popUpTo("home") }
                            UserRole.ADVISOR -> navController.navigate("dashboard_advisor") { popUpTo("home") }
                            UserRole.WARDEN -> navController.navigate("dashboard_warden") { popUpTo("home") }
                            UserRole.ADMIN -> navController.navigate("dashboard_admin") { popUpTo("home") }
                            else -> {}
                        }
                    },
                    onBack = { navController.popBackStack() }
                )
            }
        }
        composable("dashboard_admin") {
            currentUser?.let { AdminDashboard(repo, onLogout = { repo.logout(); navController.navigate("home") }) }
        }
        composable("dashboard_advisor") {
            currentUser?.let { AdvisorDashboard(it, repo, onLogout = { repo.logout(); navController.navigate("home") }) }
        }
        composable("dashboard_student") {
            currentUser?.let { StudentDashboard(it, repo, onLogout = { repo.logout(); navController.navigate("home") }) }
        }
        composable("dashboard_parent") {
            currentUser?.let { ParentDashboard(it, repo, onLogout = { repo.logout(); navController.navigate("home") }) }
        }
        composable("dashboard_warden") {
            currentUser?.let { WardenDashboard(it, repo, onLogout = { repo.logout(); navController.navigate("home") }) }
        }
    }
}

// ============================================================================
// 5. HOMEPAGE
// ============================================================================

@Composable
fun HomeScreen(navController: NavHostController) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Girls Hostel Gate Pass", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("Online Entry & Exit Management", style = MaterialTheme.typography.bodyMedium, color = Color.Gray)
        Spacer(modifier = Modifier.height(32.dp))

        Button(onClick = { navController.navigate("login/STUDENT") }, modifier = Modifier.fillMaxWidth().height(54.dp)) {
            Text("1. Student Login (ID provided by Advisor)")
        }
        Spacer(modifier = Modifier.height(12.dp))

        Button(onClick = { navController.navigate("login/ADVISOR") }, modifier = Modifier.fillMaxWidth().height(54.dp)) {
            Text("2. Advisor Login")
        }
        Spacer(modifier = Modifier.height(12.dp))

        Button(onClick = { navController.navigate("login/PARENT") }, modifier = Modifier.fillMaxWidth().height(54.dp)) {
            Text("3. Parent Portal (Register / Login)")
        }
        Spacer(modifier = Modifier.height(12.dp))

        Button(onClick = { navController.navigate("login/WARDEN") }, modifier = Modifier.fillMaxWidth().height(54.dp)) {
            Text("4. Warden Login")
        }
        Spacer(modifier = Modifier.height(32.dp))

        OutlinedButton(onClick = { navController.navigate("login/ADMIN") }, modifier = Modifier.fillMaxWidth()) {
            Text("System Admin Portal (Add Advisor / Warden)")
        }
    }
}

// ============================================================================
// 6. LOGIN SCREENS (SIMPLE ID FOR STUDENT/ADVISOR/WARDEN; GMAIL/PHONE FOR PARENT)
// ============================================================================

@Composable
fun StandardLoginScreen(
    role: UserRole,
    repo: GatePassRepository,
    onLoginSuccess: (UserProfile) -> Unit,
    onBack: () -> Unit
) {
    var identifier by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var errorMsg by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val hintText = when (role) {
        UserRole.STUDENT -> "User ID given by Advisor (e.g. shreya123 or shreya@123)"
        UserRole.ADVISOR, UserRole.WARDEN -> "Staff User ID (e.g. adv101 or warden@1)"
        else -> "Admin Email (e.g. admin@hostel.com)"
    }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center) {
        Text("${role.name} LOGIN", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(text = hintText, color = Color.Gray, style = MaterialTheme.typography.bodySmall)
        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = identifier,
            onValueChange = { identifier = it },
            label = { Text(if (role == UserRole.ADMIN) "Admin Email" else "User ID (e.g. shreya123)") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(8.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(16.dp))

        errorMsg?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        Spacer(modifier = Modifier.height(8.dp))

        Button(
            onClick = {
                scope.launch {
                    loading = true; errorMsg = null
                    repo.loginUser(identifier, password, role)
                        .onSuccess { onLoginSuccess(it) }
                        .onFailure { errorMsg = it.message }
                    loading = false
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !loading
        ) {
            Text(if (loading) "Logging in..." else "Login")
        }
        TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Back to Home") }
    }
}

@Composable
fun ParentAuthScreen(
    repo: GatePassRepository,
    onAuthSuccess: (UserProfile) -> Unit,
    onBack: () -> Unit
) {
    var isRegisterMode by remember { mutableStateOf(false) }
    var fullName by remember { mutableStateOf("") }
    var idOrGmail by remember { mutableStateOf("") }
    var phoneForReg by remember { mutableStateOf("+91") }
    var loginInput by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var feedbackMsg by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = if (isRegisterMode) "CREATE PARENT ACCOUNT" else "PARENT LOGIN",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(8.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = !isRegisterMode,
                onClick = { isRegisterMode = false; feedbackMsg = null },
                label = { Text("Login") }
            )
            FilterChip(
                selected = isRegisterMode,
                onClick = { isRegisterMode = true; feedbackMsg = null },
                label = { Text("Create Account First") }
            )
        }
        Spacer(modifier = Modifier.height(12.dp))

        if (isRegisterMode) {
            Text(
                "Create your Parent account first using the mobile number registered with the Advisor.",
                style = MaterialTheme.typography.bodySmall,
                color = Color.Gray
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = fullName,
                onValueChange = { fullName = it },
                label = { Text("Parent Full Name") },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = phoneForReg,
                onValueChange = { phoneForReg = it },
                label = { Text("Registered Mobile (+91XXXXXXXXXX)") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = idOrGmail,
                onValueChange = { idOrGmail = it },
                label = { Text("Gmail (verified) or Custom ID (optional)") },
                modifier = Modifier.fillMaxWidth()
            )
        } else {
            Text(
                "Login with your Registered Phone Number or Gmail/ID.",
                style = MaterialTheme.typography.bodySmall,
                color = Color.Gray
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = loginInput,
                onValueChange = { loginInput = it },
                label = { Text("Phone Number (+91...) or Gmail / ID") },
                modifier = Modifier.fillMaxWidth()
            )
        }

        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(16.dp))

        feedbackMsg?.let {
            Text(
                text = it,
                color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(modifier = Modifier.height(8.dp))
        }

        Button(
            onClick = {
                scope.launch {
                    loading = true; feedbackMsg = null
                    if (isRegisterMode) {
                        repo.registerParentAccount(fullName, idOrGmail, phoneForReg, password)
                            .onSuccess { msg ->
                                isError = false
                                feedbackMsg = msg
                                if (!idOrGmail.lowercase().contains("@gmail.")) {
                                    repo.loginUser(phoneForReg, password, UserRole.PARENT)
                                        .onSuccess { onAuthSuccess(it) }
                                } else {
                                    isRegisterMode = false
                                }
                            }
                            .onFailure {
                                isError = true
                                feedbackMsg = it.message
                            }
                    } else {
                        repo.loginUser(loginInput, password, UserRole.PARENT)
                            .onSuccess { onAuthSuccess(it) }
                            .onFailure {
                                isError = true
                                feedbackMsg = it.message
                            }
                    }
                    loading = false
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !loading
        ) {
            Text(if (loading) "Please wait..." else if (isRegisterMode) "Create Parent Account" else "Login")
        }

        TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Back to Home") }
    }
}

fun sendFirebaseOtp(
    activity: Activity,
    phone: String,
    onCodeSent: (String) -> Unit,
    onVerified: () -> Unit,
    onError: (String) -> Unit
) {
    val callbacks = object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
        override fun onVerificationCompleted(credential: PhoneAuthCredential) {
            onVerified()
        }
        override fun onVerificationFailed(e: FirebaseException) {
            onError(e.message ?: "OTP Request Failed")
        }
        override fun onCodeSent(verId: String, token: PhoneAuthProvider.ForceResendingToken) {
            onCodeSent(verId)
        }
    }
    val options = PhoneAuthOptions.newBuilder(FirebaseAuth.getInstance())
        .setPhoneNumber(phone)
        .setTimeout(60L, TimeUnit.SECONDS)
        .setActivity(activity)
        .setCallbacks(callbacks)
        .build()
    PhoneAuthProvider.verifyPhoneNumber(options)
}

// ============================================================================
// 7. ADMIN DASHBOARD (CREATE ADVISOR & WARDEN WITH SIMPLE ID LIKE "adv101")
// ============================================================================

@Composable
fun AdminDashboard(repo: GatePassRepository, onLogout: () -> Unit) {
    var name by remember { mutableStateOf("") }
    var customId by remember { mutableStateOf("") }
    var phone by remember { mutableStateOf("+91") }
    var password by remember { mutableStateOf("") }
    var selectedRole by remember { mutableStateOf(UserRole.ADVISOR) }
    var msg by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("Admin Control Panel", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            TextButton(onClick = onLogout) { Text("Logout") }
        }
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
        Text("Create Advisor or Warden (Give Simple ID)", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(12.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            FilterChip(selected = selectedRole == UserRole.ADVISOR, onClick = { selectedRole = UserRole.ADVISOR }, label = { Text("Advisor") })
            FilterChip(selected = selectedRole == UserRole.WARDEN, onClick = { selectedRole = UserRole.WARDEN }, label = { Text("Warden") })
        }

        OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Full Name") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = customId, onValueChange = { customId = it }, label = { Text("Assign Simple ID (e.g. adv101 or warden@1)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = phone, onValueChange = { phone = it }, label = { Text("Mobile (+91XXXXXXXXXX)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("Assign Password") }, modifier = Modifier.fillMaxWidth())
        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                scope.launch {
                    loading = true; msg = null
                    val validPhone = AuthValidator.normalizeAndValidatePhone(phone).getOrElse {
                        isError = true; msg = it.message; loading = false; return@launch
                    }
                    val profile = UserProfile(role = selectedRole.name, fullName = name.trim(), phone = validPhone)
                    repo.createAccountWithoutLogout(customId, password, profile)
                        .onSuccess { resMsg ->
                            isError = false
                            msg = resMsg
                            name = ""; customId = ""; phone = "+91"; password = ""
                        }
                        .onFailure {
                            isError = true
                            msg = "Error: ${it.message}"
                        }
                    loading = false
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !loading
        ) {
            Text(if (loading) "Creating Staff Account..." else "Create ${selectedRole.name}")
        }
        msg?.let {
            Spacer(modifier = Modifier.height(12.dp))
            Text(it, color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
        }
    }
}

// ============================================================================
// 8. ADVISOR DASHBOARD (CREATE STUDENTS WITH ID LIKE "shreya123")
// ============================================================================

@Composable
fun AdvisorDashboard(advisor: UserProfile, repo: GatePassRepository, onLogout: () -> Unit) {
    var tabIndex by remember { mutableIntStateOf(0) }
    val passes by repo.streamAdvisorPasses(advisor.uid).collectAsState(initial = emptyList())
    val scope = rememberCoroutineScope()

    var sName by remember { mutableStateOf("") }
    var sRoll by remember { mutableStateOf("") }
    var sRoom by remember { mutableStateOf("") }
    var sCustomId by remember { mutableStateOf("") }
    var sPass by remember { mutableStateOf("") }
    var sParentPhone by remember { mutableStateOf("+91") }
    var statusMsg by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("Advisor: ${advisor.fullName} (${advisor.loginId})", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            TextButton(onClick = onLogout) { Text("Logout") }
        }
        TabRow(selectedTabIndex = tabIndex) {
            Tab(selected = tabIndex == 0, onClick = { tabIndex = 0 }, text = { Text("Gate Pass Requests (${passes.size})") })
            Tab(selected = tabIndex == 1, onClick = { tabIndex = 1 }, text = { Text("Register Student") })
        }
        Spacer(modifier = Modifier.height(12.dp))

        if (tabIndex == 0) {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(passes) { pass ->
                    PassRecordCard(pass = pass) {
                        if (pass.status == PassStatus.PENDING_ADVISOR.name) {
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = {
                                        scope.launch {
                                            repo.updatePassStatus(
                                                pass.passId,
                                                PassStatus.PENDING_PARENT,
                                                "Approved by Advisor (${advisor.fullName}). Forwarded to Parent (${pass.parentPhone})."
                                            )
                                        }
                                    },
                                    modifier = Modifier.weight(1f)
                                ) { Text("Approve -> Send to Parent") }

                                OutlinedButton(
                                    onClick = {
                                        scope.launch {
                                            repo.updatePassStatus(pass.passId, PassStatus.REJECTED_ADVISOR, "Rejected by Advisor (${advisor.fullName}).")
                                        }
                                    },
                                    modifier = Modifier.weight(1f)
                                ) { Text("Reject") }
                            }
                        }
                    }
                }
            }
        } else {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                Text("Give Student a Simple ID (e.g. shreya123 or shreya@123)", fontWeight = FontWeight.SemiBold)
                OutlinedTextField(value = sName, onValueChange = { sName = it }, label = { Text("Student Full Name (e.g. Shreya)") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = sRoll, onValueChange = { sRoll = it }, label = { Text("Roll Number") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = sRoom, onValueChange = { sRoom = it }, label = { Text("Hostel Room Number") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = sCustomId, onValueChange = { sCustomId = it }, label = { Text("Simple Student ID (e.g. shreya123)") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = sPass, onValueChange = { sPass = it }, label = { Text("Assign Password") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = sParentPhone, onValueChange = { sParentPhone = it }, label = { Text("Parent Mobile (+91XXXXXXXXXX)") }, modifier = Modifier.fillMaxWidth())
                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = {
                        scope.launch {
                            val validParentPhone = AuthValidator.normalizeAndValidatePhone(sParentPhone).getOrElse {
                                isError = true; statusMsg = it.message; return@launch
                            }
                            val studentProfile = UserProfile(
                                role = UserRole.STUDENT.name,
                                fullName = sName.trim(),
                                rollNumber = sRoll.trim(),
                                roomNumber = sRoom.trim(),
                                advisorId = advisor.uid,
                                parentPhone = validParentPhone
                            )
                            repo.createAccountWithoutLogout(sCustomId, sPass, studentProfile)
                                .onSuccess { msg ->
                                    isError = false
                                    statusMsg = msg
                                    sName = ""; sRoll = ""; sRoom = ""; sCustomId = ""; sPass = ""; sParentPhone = "+91"
                                }
                                .onFailure {
                                    isError = true
                                    statusMsg = "Error: ${it.message}"
                                }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Create Student ID & Password") }
                statusMsg?.let {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(it, color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

// ============================================================================
// 9. STUDENT DASHBOARD
// ============================================================================

@Composable
fun StudentDashboard(student: UserProfile, repo: GatePassRepository, onLogout: () -> Unit) {
    val passes by repo.streamStudentPasses(student.uid).collectAsState(initial = emptyList())
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    var date by remember { mutableStateOf("") }
    var destination by remember { mutableStateOf("") }
    var reason by remember { mutableStateOf("") }
    var outTiming by remember { mutableStateOf("") }
    var inTiming by remember { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Column {
                Text("Student: ${student.fullName} (ID: ${student.loginId})", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("Room: ${student.roomNumber} | Parent: ${student.parentPhone}", style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = onLogout) { Text("Logout") }
        }
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("Apply for Gate Pass (Cannot be edited after submission)", fontWeight = FontWeight.Bold)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(value = date, onValueChange = { date = it }, label = { Text("Date (DD/MM/YY)") }, modifier = Modifier.weight(1f))
                    OutlinedTextField(value = destination, onValueChange = { destination = it }, label = { Text("Where to go") }, modifier = Modifier.weight(1f))
                }
                OutlinedTextField(value = reason, onValueChange = { reason = it }, label = { Text("Reason for going") }, modifier = Modifier.fillMaxWidth())
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(value = outTiming, onValueChange = { outTiming = it }, label = { Text("Out Time (e.g. 10 AM)") }, modifier = Modifier.weight(1f))
                    OutlinedTextField(value = inTiming, onValueChange = { inTiming = it }, label = { Text("Return Time (e.g. 5 PM)") }, modifier = Modifier.weight(1f))
                }
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = {
                        if (date.isBlank() || destination.isBlank() || reason.isBlank() || outTiming.isBlank()) {
                            Toast.makeText(context, "Fill all fields carefully. You cannot edit later.", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        scope.launch {
                            val pass = GatePass(
                                studentId = student.uid,
                                studentName = student.fullName,
                                roomNumber = student.roomNumber,
                                advisorId = student.advisorId,
                                parentPhone = student.parentPhone,
                                date = date,
                                destination = destination,
                                reason = reason,
                                outTiming = outTiming,
                                expectedInTiming = inTiming
                            )
                            repo.submitGatePass(pass).onSuccess {
                                date = ""; destination = ""; reason = ""; outTiming = ""; inTiming = ""
                                Toast.makeText(context, "Pass Submitted to Advisor!", Toast.LENGTH_SHORT).show()
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Submit Gate Pass Request") }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
        Text("My Gate Pass Status & Records", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(8.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(passes) { pass ->
                PassRecordCard(pass = pass) {
                    if (pass.status == PassStatus.APPROVED_EXIT.name) {
                        Button(
                            onClick = {
                                scope.launch {
                                    repo.updatePassStatus(
                                        pass.passId,
                                        PassStatus.ENTRY_INITIATED,
                                        "Student initiated Return Entry. Sent directly to Parent (${pass.parentPhone}), Advisor, and Warden."
                                    )
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text("Mark Hostel Return (Direct Entry to Parent)") }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 10. PARENT DASHBOARD (OTP VERIFICATION ONLY WHEN CLICKING "ALLOW EXIT")
// ============================================================================

@Composable
fun ParentDashboard(parent: UserProfile, repo: GatePassRepository, onLogout: () -> Unit) {
    val passes by repo.streamParentPasses(parent.phone).collectAsState(initial = emptyList())
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var activePassForOtp by remember { mutableStateOf<GatePass?>(null) }
    var verificationId by remember { mutableStateOf<String?>(null) }
    var otpCode by remember { mutableStateOf("") }
    var verifyingOtp by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Column {
                Text("Parent: ${parent.fullName}", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("Registered Phone: ${parent.phone}", style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = onLogout) { Text("Logout") }
        }
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        if (activePassForOtp != null) {
            AlertDialog(
                onDismissRequest = { activePassForOtp = null; verificationId = null; otpCode = "" },
                title = { Text("OTP Verification Required") },
                text = {
                    Column {
                        Text("Allowing exit for ${activePassForOtp!!.studentName} to ${activePassForOtp!!.destination}. Enter the OTP sent to ${parent.phone}.")
                        Spacer(modifier = Modifier.height(12.dp))
                        if (verificationId == null) {
                            CircularProgressIndicator(modifier = Modifier.size(28.dp))
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Sending OTP to ${parent.phone}...")
                        } else {
                            OutlinedTextField(
                                value = otpCode,
                                onValueChange = { otpCode = it },
                                label = { Text("Enter 6-digit OTP") },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }
                },
                confirmButton = {
                    if (verificationId != null) {
                        Button(
                            onClick = {
                                scope.launch {
                                    verifyingOtp = true
                                    repo.verifyParentOtpIsolated(verificationId!!, otpCode)
                                        .onSuccess {
                                            val targetPass = activePassForOtp!!
                                            repo.updatePassStatus(
                                                targetPass.passId,
                                                PassStatus.APPROVED_EXIT,
                                                "Parent (${parent.fullName}) permitted exit via OTP on ${parent.phone}. Msg sent to Advisor & Warden."
                                            )
                                            activePassForOtp = null; verificationId = null; otpCode = ""
                                            Toast.makeText(context, "Pass Approved! Advisor & Warden notified.", Toast.LENGTH_SHORT).show()
                                        }
                                        .onFailure {
                                            Toast.makeText(context, "Invalid OTP: ${it.message}", Toast.LENGTH_SHORT).show()
                                        }
                                    verifyingOtp = false
                                }
                            },
                            enabled = !verifyingOtp
                        ) { Text(if (verifyingOtp) "Verifying..." else "Verify OTP & Allow") }
                    }
                },
                dismissButton = {
                    TextButton(onClick = { activePassForOtp = null; verificationId = null; otpCode = "" }) { Text("Cancel") }
                }
            )
        }

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(passes) { pass ->
                PassRecordCard(pass = pass) {
                    if (pass.status == PassStatus.PENDING_PARENT.name) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    activePassForOtp = pass
                                    sendFirebaseOtp(
                                        activity = context as Activity,
                                        phone = parent.phone,
                                        onCodeSent = { vId -> verificationId = vId },
                                        onVerified = {
                                            scope.launch {
                                                repo.updatePassStatus(
                                                    pass.passId,
                                                    PassStatus.APPROVED_EXIT,
                                                    "Parent (${parent.fullName}) permitted exit via auto-verified OTP. Advisor & Warden notified."
                                                )
                                                activePassForOtp = null
                                            }
                                        },
                                        onError = { err ->
                                            activePassForOtp = null
                                            Toast.makeText(context, err, Toast.LENGTH_LONG).show()
                                        }
                                    )
                                },
                                modifier = Modifier.weight(1f)
                            ) { Text("Allow Exit (Verify OTP)") }

                            OutlinedButton(
                                onClick = {
                                    scope.launch {
                                        repo.updatePassStatus(
                                            pass.passId,
                                            PassStatus.REJECTED_PARENT,
                                            "Rejected by Parent (${parent.fullName})."
                                        )
                                    }
                                },
                                modifier = Modifier.weight(1f)
                            ) { Text("Reject") }
                        }
                    }

                    if (pass.status == PassStatus.ENTRY_INITIATED.name) {
                        Button(
                            onClick = {
                                scope.launch {
                                    repo.updatePassStatus(
                                        pass.passId,
                                        PassStatus.ENTRY_COMPLETED,
                                        "Parent (${parent.fullName}) confirmed Student Return Entry. Record updated for Advisor & Warden."
                                    )
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text("Confirm Student Return Entry (Notify Advisor & Warden)") }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 11. WARDEN DASHBOARD & REUSABLE RECORD CARD
// ============================================================================

@Composable
fun WardenDashboard(warden: UserProfile, repo: GatePassRepository, onLogout: () -> Unit) {
    val passes by repo.streamAllPassesForWarden().collectAsState(initial = emptyList())

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("Warden: ${warden.fullName} (ID: ${warden.loginId})", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            TextButton(onClick = onLogout) { Text("Logout") }
        }
        Text("Live Gate Pass Records & Notifications", color = Color.Gray)
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(passes) { pass ->
                PassRecordCard(pass = pass) {}
            }
        }
    }
}

@Composable
fun PassRecordCard(pass: GatePass, actionContent: @Composable () -> Unit) {
    val statusColor = when (pass.status) {
        PassStatus.APPROVED_EXIT.name, PassStatus.ENTRY_COMPLETED.name -> Color(0xFF2E7D32)
        PassStatus.REJECTED_ADVISOR.name, PassStatus.REJECTED_PARENT.name -> Color(0xFFC62828)
        else -> Color(0xFFEF6C00)
    }

    Card(modifier = Modifier.fillMaxWidth(), elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("${pass.studentName} (Room: ${pass.roomNumber})", fontWeight = FontWeight.Bold)
                Text(
                    text = pass.status,
                    color = Color.White,
                    modifier = Modifier.background(statusColor, shape = MaterialTheme.shapes.small).padding(horizontal = 8.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelSmall
                )
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text("Date: ${pass.date} | Timing: ${pass.outTiming} - ${pass.expectedInTiming}")
            Text("Destination: ${pass.destination}")
            Text("Reason: ${pass.reason}")
            Text("Parent Phone: ${pass.parentPhone}", style = MaterialTheme.typography.bodySmall, color = Color.Gray)

            if (pass.notificationLog.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text("Audit & Notification Trail:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
                pass.notificationLog.forEach { log ->
                    Text("• $log", style = MaterialTheme.typography.bodySmall, color = Color.DarkGray)
                }
            }

            Spacer(modifier = Modifier.height(10.dp))
            actionContent()
        }
    }
}