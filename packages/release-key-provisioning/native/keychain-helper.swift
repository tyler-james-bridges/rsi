import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let service = "dev.rsi.macbook.release-signing"
private let account = "release-ed25519-v1"
private let label = "RSI foundation release signing key"
private let pkcs8Prefix: [UInt8] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]
private let releaseSignatureDomain = Data("rsi-signed-release-bundle-manifest-v1\0".utf8)
private let tagSignaturePrefix = Data([
    0x53, 0x53, 0x48, 0x53, 0x49, 0x47, // SSHSIG
    0x00, 0x00, 0x00, 0x03, 0x67, 0x69, 0x74, // namespace: git
    0x00, 0x00, 0x00, 0x00, // reserved: empty
    0x00, 0x00, 0x00, 0x06, 0x73, 0x68, 0x61, 0x35, 0x31, 0x32, // hash: sha512
    0x00, 0x00, 0x00, 0x40, // 64-byte message hash follows
])
private let maximumSigningMessageBytes = 256 * 1024

private enum Exit: Int32 {
    case ok = 0
    case absent = 2
    case refused = 3
    case invalid = 4
}

private func baseQuery() -> [CFString: Any] {
    return [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecUseDataProtectionKeychain: true,
    ]
}

private func expectedAccessControl() -> SecAccessControl? {
    var error: Unmanaged<CFError>?
    let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.userPresence],
        &error
    )
    error?.release()
    return access
}

private func decodeBase64urlByte(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 65...90: return byte - 65
    case 97...122: return byte - 97 + 26
    case 48...57: return byte - 48 + 52
    case 45: return 62
    case 95: return 63
    default: return nil
    }
}

private func hasPkcs8Prefix(_ data: Data) -> Bool {
    guard data.count == 48 else { return false }
    return data.withUnsafeBytes { raw in
        let bytes = raw.bindMemory(to: UInt8.self)
        var difference: UInt8 = 0
        for index in 0..<pkcs8Prefix.count {
            difference |= bytes[index] ^ pkcs8Prefix[index]
        }
        return difference == 0
    }
}

private func decodeBase64url(_ encoded: inout Data) -> Data? {
    guard encoded.count == 64 else { return nil }
    var decoded = Data(count: 48)
    var valid = true
    encoded.withUnsafeBytes { sourceRaw in
        decoded.withUnsafeMutableBytes { destinationRaw in
            let source = sourceRaw.bindMemory(to: UInt8.self)
            let destination = destinationRaw.bindMemory(to: UInt8.self)
            guard source.count == 64, destination.count == 48 else {
                valid = false
                return
            }
            for group in 0..<16 {
                guard let first = decodeBase64urlByte(source[group * 4]),
                      let second = decodeBase64urlByte(source[group * 4 + 1]),
                      let third = decodeBase64urlByte(source[group * 4 + 2]),
                      let fourth = decodeBase64urlByte(source[group * 4 + 3]) else {
                    valid = false
                    return
                }
                destination[group * 3] = (first << 2) | (second >> 4)
                destination[group * 3 + 1] = (second << 4) | (third >> 2)
                destination[group * 3 + 2] = (third << 6) | fourth
            }
        }
    }
    guard valid, hasPkcs8Prefix(decoded) else {
        decoded.resetBytes(in: 0..<decoded.count)
        return nil
    }
    return decoded
}

private func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    left.withUnsafeBytes { leftRaw in
        right.withUnsafeBytes { rightRaw in
            let leftBytes = leftRaw.bindMemory(to: UInt8.self)
            let rightBytes = rightRaw.bindMemory(to: UInt8.self)
            for index in 0..<left.count {
                difference |= leftBytes[index] ^ rightBytes[index]
            }
        }
    }
    return difference == 0
}

private func readBoundedStandardInput(maximumBytes: Int) -> Data? {
    var result = Data()
    while true {
        let chunk = FileHandle.standardInput.availableData
        if chunk.isEmpty { return result }
        if result.count > maximumBytes - chunk.count {
            result.resetBytes(in: 0..<result.count)
            return nil
        }
        result.append(chunk)
    }
}

private func readStoredKey(localizedReason: String) -> Data? {
    guard let expectedAccess = expectedAccessControl() else { return nil }
    var query = baseQuery()
    query[kSecReturnAttributes] = true
    query[kSecReturnData] = true
    query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
    query[kSecMatchLimit] = kSecMatchLimitAll
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate() }
    context.localizedReason = localizedReason
    query[kSecUseAuthenticationContext] = context
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
          let items = itemDictionaries(result),
          items.count == 1,
          let attributes = items.first,
          let storedKeyData = attributes[kSecValueData] as? Data,
          attributes[kSecAttrService] as? String == service,
          attributes[kSecAttrAccount] as? String == account,
          attributes[kSecAttrLabel] as? String == label,
          attributes[kSecAttrAccessible] as? String
              == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String),
          let synchronizable = attributes[kSecAttrSynchronizable] as? Bool,
          synchronizable == false,
          let actualAccess = attributes[kSecAttrAccessControl],
          CFEqual(actualAccess as CFTypeRef, expectedAccess) else {
        return nil
    }
    return storedKeyData
}

private func itemDictionaries(_ result: CFTypeRef?) -> [[CFString: Any]]? {
    if let items = result as? [[CFString: Any]] { return items }
    if let item = result as? [CFString: Any] { return [item] }
    return nil
}

private func addCreateOnly() -> Exit {
    guard var encoded = readBoundedStandardInput(maximumBytes: 64) else { return .invalid }
    defer { encoded.resetBytes(in: 0..<encoded.count) }
    guard var keyData = decodeBase64url(&encoded), let access = expectedAccessControl() else {
        return .invalid
    }
    defer { keyData.resetBytes(in: 0..<keyData.count) }
    var query = baseQuery()
    query[kSecAttrLabel] = label
    query[kSecAttrSynchronizable] = false
    query[kSecAttrAccessControl] = access
    query[kSecValueData] = keyData
    let status = SecItemAdd(query as CFDictionary, nil)
    return status == errSecSuccess ? .ok : .refused
}

private func presence() -> Exit {
    var query = baseQuery()
    query[kSecReturnAttributes] = true
    query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
    query[kSecMatchLimit] = kSecMatchLimitAll
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate() }
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecSuccess {
        guard let items = itemDictionaries(result), items.count == 1,
              let attributes = items.first,
              attributes[kSecAttrService] as? String == service,
              attributes[kSecAttrAccount] as? String == account,
              let synchronizable = attributes[kSecAttrSynchronizable] as? Bool,
              synchronizable == false else {
            return .refused
        }
        return .ok
    }
    if status == errSecInteractionNotAllowed { return .ok }
    return status == errSecItemNotFound ? .absent : .refused
}

private func verify() -> Exit {
    guard var encoded = readBoundedStandardInput(maximumBytes: 64) else { return .invalid }
    defer { encoded.resetBytes(in: 0..<encoded.count) }
    guard var expectedKeyData = decodeBase64url(&encoded) else { return .invalid }
    defer { expectedKeyData.resetBytes(in: 0..<expectedKeyData.count) }
    guard var storedKeyData = readStoredKey(
        localizedReason: "Authorize verification of the fixed RSI foundation release identity"
    ) else {
        return .refused
    }
    defer { storedKeyData.resetBytes(in: 0..<storedKeyData.count) }
    return constantTimeEqual(storedKeyData, expectedKeyData) ? .ok : .refused
}

private func isReleaseSigningMessage(_ message: Data) -> Bool {
    return message.count > releaseSignatureDomain.count + 1
        && message.count <= maximumSigningMessageBytes
        && message.starts(with: releaseSignatureDomain)
        && message[releaseSignatureDomain.count] == 0x7b
        && message.last == 0x7d
}

private func isTagSigningMessage(_ message: Data) -> Bool {
    return message.count == tagSignaturePrefix.count + 64
        && message.starts(with: tagSignaturePrefix)
}

private func signFixedDomain(isTag: Bool) -> Exit {
    guard var message = readBoundedStandardInput(maximumBytes: maximumSigningMessageBytes),
          isTag ? isTagSigningMessage(message) : isReleaseSigningMessage(message),
          var keyData = readStoredKey(
              localizedReason: isTag
                  ? "Authorize the RSI foundation tag signature"
                  : "Authorize the RSI foundation release-manifest signature"
          ),
          hasPkcs8Prefix(keyData) else {
        return .refused
    }
    defer {
        message.resetBytes(in: 0..<message.count)
        keyData.resetBytes(in: 0..<keyData.count)
    }
    var seed = Data(keyData.suffix(32))
    defer { seed.resetBytes(in: 0..<seed.count) }
    do {
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        var signature = try privateKey.signature(for: message)
        defer { signature.resetBytes(in: 0..<signature.count) }
        guard signature.count == 64 else { return .refused }
        FileHandle.standardOutput.write(signature)
        return .ok
    } catch {
        return .refused
    }
}

private let arguments = CommandLine.arguments
private let result: Exit
if arguments.count != 2 {
    result = .invalid
} else {
    switch arguments[1] {
    case "add": result = addCreateOnly()
    case "presence": result = presence()
    case "verify": result = verify()
    case "sign-release": result = signFixedDomain(isTag: false)
    case "sign-tag": result = signFixedDomain(isTag: true)
    default: result = .invalid
    }
}
Foundation.exit(result.rawValue)
