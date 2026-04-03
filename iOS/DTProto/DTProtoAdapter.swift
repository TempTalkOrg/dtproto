//
//  DTProtoAdapter.swift
//
//  Created by TempTalkOrg.
//

import Foundation

@objc
public class DTEncryptedMsgResult: NSObject {
    
    @objc
    public let cipherText: Data
    
    @objc
    public let signedEKey: Data
    
    @objc
    public let eKey: Data
    
    @objc
    public let identityKey: Data
    
    @objc
    public let ermKeys: [String: Data]?
    
    
    init(cipherText: Data, signedEKey: Data, eKey: Data, identityKey: Data, ermKeys: [String: Data]?) {
        self.cipherText = cipherText
        self.signedEKey = signedEKey
        self.eKey = eKey
        self.identityKey = identityKey
        self.ermKeys = ermKeys
        super.init()
    }
    
}

@objc
public enum DTIdentityVerifyResult: Int {
    case match = 0
    case cacheOutdated = 1
    case senderKeyUpdated = 2
    case allMismatch = 3
}

@objc
public class DTDecryptedMsgResult: NSObject {

    @objc
    public let plainText: Data

    @objc
    public let identityVerifyResult: DTIdentityVerifyResult

    init(plainText: Data, identityVerifyResult: DTIdentityVerifyResult) {
        self.plainText = plainText
        self.identityVerifyResult = identityVerifyResult
        super.init()
    }

}


@objc
public class DTProtoAdapter: NSObject {
    
    @objc
    public func decryptMessage(version: Int32, signedEKey: Data, theirIdKey: Data, localTheirIdKey: Data, cachedTheirIdKey: Data?, eKey: Data, localPriKey: Data, ermKey: Data, cipherText: Data) throws -> DTDecryptedMsgResult {
        let cachedKey: [UInt8]? = cachedTheirIdKey?.bytes
        let decryptedMessage = try DtProto(version: version).decryptMessage(signedEKey: signedEKey.bytes, theirIdKey: theirIdKey.bytes, localTheirIdKey: localTheirIdKey.bytes, cachedTheirIdKey: cachedKey, eKey: eKey.bytes, localPriKey: localPriKey.bytes, ermKey: ermKey.bytes, cipherText: cipherText.bytes)

        let verifyResult: DTIdentityVerifyResult
        switch decryptedMessage.identityVerifyResult {
        case .match:
            verifyResult = .match
        case .cacheOutdated:
            verifyResult = .cacheOutdated
        case .senderKeyUpdated:
            verifyResult = .senderKeyUpdated
        case .allMismatch:
            verifyResult = .allMismatch
        }

        return DTDecryptedMsgResult(plainText: decryptedMessage.plainText.data,
                                    identityVerifyResult: verifyResult)
    }

    @objc
    public func encryptMessage(version: Int32, pubIdKey: Data, pubIdKeys: [String: Data], localPriKey: Data, plainText: Data) throws -> DTEncryptedMsgResult {
        let bytesDict = pubIdKeys.mapValues { value in
            value.bytes
        }
        let encryptedMessage = try DtProto(version: version).encryptMessage(pubIdKey: pubIdKey.bytes, pubIdKeys: bytesDict, localPriKey: localPriKey.bytes, plainText: plainText.bytes)

        let bytesErmKeys = encryptedMessage.ermKeys?.mapValues({ value in
            value.data
        })

        return DTEncryptedMsgResult(cipherText: encryptedMessage.cipherText.data,
                                    signedEKey: encryptedMessage.signedEKey.data,
                                    eKey: encryptedMessage.eKey.data,
                                    identityKey: encryptedMessage.identityKey.data,
                                    ermKeys: bytesErmKeys)
    }
}

extension Data {
    var bytes: [UInt8] {
        return [UInt8](self)
    }
}

extension Array where Element == UInt8 {
    var data: Data {
        return Data(self)
    }
}
