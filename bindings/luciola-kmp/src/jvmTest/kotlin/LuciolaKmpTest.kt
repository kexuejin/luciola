package uniffi.luciola_uniffi

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class LuciolaKmpTest {
    @Test
    fun testKotlinBindingApi() {
        // Test that functions can be called cleanly in Kotlin
        val isVirt = isVirtualNic("utun5")
        assertTrue(isVirt, "utun5 should be recognized as virtual NIC")

        val isTun = isTunVirtualIp("198.18.0.1")
        assertTrue(isTun, "198.18.0.1 should be recognized as TUN benchmark IP")

        val qr = renderQrAscii("http://192.168.2.82:8080")
        assertNotNull(qr, "Terminal QR code should be generated")

        val meta = getDeviceMeta()
        assertNotNull(meta.os)
        assertNotNull(meta.arch)
    }
}
