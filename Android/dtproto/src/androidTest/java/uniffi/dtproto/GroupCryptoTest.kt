package uniffi.dtproto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 群加密模块集成测试
 *
 * 在 Android 模拟器/真机上运行，验证 .so 加载和 UniFFI 绑定正确性。
 * 使用与 Rust 端相同的跨平台测试向量，确保各端一致。
 */
@RunWith(AndroidJUnit4::class)
class GroupCryptoTest {

    // ── 跨平台测试向量 ──────────────────────────

    /** r_group = [0x00, 0x01, ..., 0x1f] */
    private val testRGroup: List<UByte> = (0..31).map { it.toUByte() }

    private val expectedKGroup = "c429ae7559b8f8a480f68e54e0becb5ef22d142e137ab10f4dd535e3a3f777ef"
    private val expectedSkBind = "aefb15f01c6e8c5bd3b03a9122a97b8198d69ce6138d833983f4ee46394e786b"
    private val expectedPkBind = "1c37ad97463331dbcfdc44a0697482fdc00e33a6462c362980c1834f5ce16d3d"
    private val expectedSignature =
        "3e6d31fed3bf0bba4d06b4eb10e2de6bb419030b973bf49fd3666ff818cda4c5" +
        "a42b109a431143a7e2200fb1023b9f6627303ed8ea9391de04cc056201eb8404"
    private val testUid = "test-uid-001"

    // ── Helper ──────────────────────────────────

    private fun List<UByte>.toHex(): String = joinToString("") { it.toString(16).padStart(2, '0') }

    private fun gc(): DtGroupCrypto = DtGroupCrypto(1u)

    // ── 1. 密钥派生 ─────────────────────────────

    @Test
    fun deriveKeys_crossPlatformVector() {
        val keys = gc().deriveKeys(testRGroup)

        assertEquals("k_group 长度", 32, keys.kGroup.size)
        assertEquals("sk_bind 长度", 32, keys.skBind.size)
        assertEquals("pk_bind 长度", 32, keys.pkBind.size)

        assertEquals("k_group 值", expectedKGroup, keys.kGroup.toHex())
        assertEquals("sk_bind 值", expectedSkBind, keys.skBind.toHex())
        assertEquals("pk_bind 值", expectedPkBind, keys.pkBind.toHex())
    }

    @Test
    fun deriveKeys_deterministic() {
        val keys1 = gc().deriveKeys(testRGroup)
        val keys2 = gc().deriveKeys(testRGroup)

        assertEquals("相同输入应产生相同 k_group", keys1.kGroup, keys2.kGroup)
        assertEquals("相同输入应产生相同 sk_bind", keys1.skBind, keys2.skBind)
        assertEquals("相同输入应产生相同 pk_bind", keys1.pkBind, keys2.pkBind)
    }

    @Test
    fun deriveKeys_invalidLength() {
        try {
            gc().deriveKeys(listOf(0x01u, 0x02u))
            fail("应抛出 InvalidRGroupLength")
        } catch (e: DtProtoException.InvalidRGroupLength) {
            // 预期
        }
    }

    // ── 2. 加解密 ───────────────────────────────

    @Test
    fun encryptDecrypt_roundtrip() {
        val keys = gc().deriveKeys(testRGroup)
        val plaintext = "hello group".toByteArray().map { it.toUByte() }
        val aad = "tt-grp-v1|gcm|name".toByteArray().map { it.toUByte() }

        val blob = gc().encrypt(keys.kGroup, plaintext, aad)
        val decrypted = gc().decrypt(keys.kGroup, blob, aad)

        assertEquals("解密结果应与明文一致", plaintext, decrypted)
    }

    @Test
    fun encryptDecrypt_blobFormat() {
        val keys = gc().deriveKeys(testRGroup)
        val plaintext = "test".toByteArray().map { it.toUByte() }
        val aad = "tt-grp-v1|gcm|name".toByteArray().map { it.toUByte() }

        val blob = gc().encrypt(keys.kGroup, plaintext, aad)

        // blob = version(1) + nonce(12) + ciphertext + tag(16)
        assertTrue("blob 长度 >= 29", blob.size >= 29)
        assertEquals("blob 版本号", 1u.toUByte(), blob[0])
    }

    @Test
    fun decrypt_wrongKey() {
        val keys = gc().deriveKeys(testRGroup)
        val wrongKey = (0..31).map { 0xFFu.toUByte() }
        val aad = "tt-grp-v1|gcm|name".toByteArray().map { it.toUByte() }

        val blob = gc().encrypt(keys.kGroup, "secret".toByteArray().map { it.toUByte() }, aad)

        try {
            gc().decrypt(wrongKey, blob, aad)
            fail("错误密钥应抛出 GroupDecryptError")
        } catch (e: DtProtoException.GroupDecryptException) {
            // 预期
        }
    }

    @Test
    fun decrypt_wrongAad() {
        val keys = gc().deriveKeys(testRGroup)
        val aad = "tt-grp-v1|gcm|name".toByteArray().map { it.toUByte() }
        val wrongAad = "tt-grp-v1|gcm|avatar".toByteArray().map { it.toUByte() }

        val blob = gc().encrypt(keys.kGroup, "secret".toByteArray().map { it.toUByte() }, aad)

        try {
            gc().decrypt(keys.kGroup, blob, wrongAad)
            fail("错误 AAD 应抛出 GroupDecryptError")
        } catch (e: DtProtoException.GroupDecryptException) {
            // 预期
        }
    }

    @Test
    fun encrypt_invalidKeyLength() {
        try {
            gc().encrypt(
                listOf(0x01u),
                "test".toByteArray().map { it.toUByte() },
                "aad".toByteArray().map { it.toUByte() }
            )
            fail("应抛出 InvalidKGroupLength")
        } catch (e: DtProtoException.InvalidKGroupLength) {
            // 预期
        }
    }

    @Test
    fun encrypt_emptyPlaintext() {
        val keys = gc().deriveKeys(testRGroup)
        try {
            gc().encrypt(keys.kGroup, emptyList(), "aad".toByteArray().map { it.toUByte() })
            fail("空 plaintext 应抛出 ParamsError")
        } catch (e: DtProtoException.ParamsException) {
            // 预期
        }
    }

    // ── 3. 签名验签 ─────────────────────────────

    @Test
    fun signVerify_crossPlatformVector() {
        val keys = gc().deriveKeys(testRGroup)
        val signature = gc().signUid(keys.skBind, testUid)

        assertEquals("签名长度", 64, signature.size)
        assertEquals("签名值", expectedSignature, signature.toHex())
    }

    @Test
    fun signVerify_roundtrip() {
        val keys = gc().deriveKeys(testRGroup)
        val signature = gc().signUid(keys.skBind, "user-abc-123")
        val valid = gc().verifyUid(keys.pkBind, "user-abc-123", signature)

        assertTrue("合法签名应验证通过", valid)
    }

    @Test
    fun verify_wrongUid() {
        val keys = gc().deriveKeys(testRGroup)
        val signature = gc().signUid(keys.skBind, "user-a")
        val valid = gc().verifyUid(keys.pkBind, "user-b", signature)

        assertFalse("不同 uid 签名应验证失败", valid)
    }

    @Test
    fun verify_tamperedSignature() {
        val keys = gc().deriveKeys(testRGroup)
        val signature = gc().signUid(keys.skBind, testUid).toMutableList()
        signature[0] = (signature[0].toInt() xor 0xFF).toUByte()

        val valid = gc().verifyUid(keys.pkBind, testUid, signature)
        assertFalse("篡改签名应验证失败", valid)
    }

    @Test
    fun signUid_emptyUid() {
        val keys = gc().deriveKeys(testRGroup)
        try {
            gc().signUid(keys.skBind, "")
            fail("空 uid 应抛出 ParamsError")
        } catch (e: DtProtoException.ParamsException) {
            // 预期
        }
    }

    @Test
    fun verifyUid_invalidPkLength() {
        try {
            gc().verifyUid(listOf(0x01u), testUid, (0..63).map { 0u.toUByte() })
            fail("应抛出 InvalidPkBindLength")
        } catch (e: DtProtoException.InvalidPkBindLength) {
            // 预期
        }
    }

    @Test
    fun verifyUid_invalidSignatureLength() {
        val keys = gc().deriveKeys(testRGroup)
        try {
            gc().verifyUid(keys.pkBind, testUid, listOf(0x01u))
            fail("应抛出 InvalidSignatureLength")
        } catch (e: DtProtoException.InvalidSignatureLength) {
            // 预期
        }
    }
}
