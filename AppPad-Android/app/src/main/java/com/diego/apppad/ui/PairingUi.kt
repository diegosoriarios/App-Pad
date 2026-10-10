package com.diego.apppad.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.diego.apppad.ble.BleServerManager
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

private val PairingChipBackground = Color(0xFF1E1E22)

private fun scannerOptions() = ScanOptions().apply {
    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
    setPrompt("Scan the QR code shown on your Mac")
    setBeepEnabled(true)
    setOrientationLocked(true)
}

/**
 * Pairing controls and status: shown under the connection banner.
 *
 * The "Pair via QR" / PIN entry points are always visible (except while a
 * session is READY) so a first-time pair can start before the Mac has
 * connected; the OTP is delivered automatically once it does.
 */
@Composable
fun PairingPanel(bleServerManager: BleServerManager) {
    val phase by bleServerManager.sessionPhase.collectAsState()
    val pairingMacName by bleServerManager.pairingMacName.collectAsState()
    val trustedMacs by bleServerManager.trustedMacs.collectAsState()
    val isWaitingToPair by bleServerManager.isWaitingToPair.collectAsState()

    var showPinDialog by remember { mutableStateOf(false) }
    var showTrustedMacs by remember { mutableStateOf(false) }

    val context = LocalContext.current
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { qrText ->
            bleServerManager.startPairingWithQr(qrText)
        }
    }
    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            scanLauncher.launch(scannerOptions())
        }
    }

    fun launchScanner() {
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        if (granted) {
            scanLauncher.launch(scannerOptions())
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = PairingChipBackground.copy(alpha = 0.85f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            when (phase) {
                BleServerManager.SessionPhase.READY -> {
                    StatusLine("🔒 Encrypted session active", Color(0xFF4CAF50))
                }
                BleServerManager.SessionPhase.NEGOTIATING -> {
                    StatusLine(
                        "Negotiating secure session${pairingMacName?.let { " with $it" } ?: ""}…",
                        Color(0xFFFFB74D)
                    )
                }
                BleServerManager.SessionPhase.PAIRING_NEEDED -> {
                    StatusLine("This Mac doesn't know this phone yet", Color(0xFFFFB74D))
                }
                BleServerManager.SessionPhase.FAILED -> {
                    StatusLine("Pairing failed — try QR or PIN again", Color(0xFFFF5252))
                }
                BleServerManager.SessionPhase.IDLE -> {
                    StatusLine("Not connected — open AirPad on your Mac", Color(0xFF9E9E9E))
                }
            }

            if (isWaitingToPair) {
                Spacer(modifier = Modifier.height(4.dp))
                StatusLine("Will pair automatically once your Mac connects", Color(0xFF9E9E9E))
            }

            if (phase != BleServerManager.SessionPhase.READY) {
                Spacer(modifier = Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Button(onClick = { launchScanner() }) {
                        Text("Pair via QR", fontSize = 12.sp)
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    TextButton(onClick = { showPinDialog = true }) {
                        Text("Enter PIN instead", fontSize = 12.sp, color = Color(0xFF9E9E9E))
                    }
                }
            }

            if (trustedMacs.isNotEmpty()) {
                Spacer(modifier = Modifier.height(4.dp))
                TextButton(onClick = { showTrustedMacs = true }) {
                    Text(
                        "Trusted Macs (${trustedMacs.size})",
                        fontSize = 11.sp,
                        color = Color(0xFF6E6E73)
                    )
                }
            }
        }
    }

    if (showPinDialog) {
        PinDialog(
            onConfirm = { pin ->
                showPinDialog = false
                bleServerManager.startPairingWithPin(pin, pairingMacName)
            },
            onDismiss = { showPinDialog = false }
        )
    }

    if (showTrustedMacs) {
        TrustedMacsDialog(
            macs = trustedMacs,
            onRemove = { bleServerManager.removeMac(it) },
            onDismiss = { showTrustedMacs = false }
        )
    }
}

@Composable
private fun StatusLine(text: String, color: Color) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium),
        color = color,
        fontSize = 12.sp
    )
}

@Composable
private fun PinDialog(onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var pin by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Enter the 6-digit PIN") },
        text = {
            Column {
                Text("Type the PIN shown under the QR code on your Mac.", fontSize = 13.sp)
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = pin,
                    onValueChange = { value ->
                        pin = value.filter { it.isDigit() }.take(6)
                    },
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = KeyboardType.NumberPassword
                    ),
                    singleLine = true,
                    placeholder = { Text("000000") }
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(pin) },
                enabled = pin.length == 6
            ) { Text("Pair") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun TrustedMacsDialog(
    macs: List<com.diego.apppad.pairing.TrustedMac>,
    onRemove: (com.diego.apppad.pairing.TrustedMac) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Trusted Macs") },
        text = {
            Column {
                for (mac in macs) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(mac.name, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                            Text(
                                "Paired ${java.text.DateFormat.getDateInstance().format(java.util.Date(mac.addedAtMillis))}",
                                fontSize = 11.sp,
                                color = Color(0xFF6E6E73)
                            )
                        }
                        TextButton(onClick = { onRemove(mac) }) {
                            Text("Remove", color = Color(0xFFFF5252), fontSize = 12.sp)
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Done") }
        }
    )
}
