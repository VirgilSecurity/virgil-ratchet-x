//
// Copyright (C) 2015-2018 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import VirgilSDK
import VSCRatchet
import VirgilCryptoApiImpl

@objc(VSRSecureChat) open class SecureChat: NSObject {
    @objc public let accessTokenProvider: AccessTokenProvider
    @objc public let identityPrivateKey: VirgilPrivateKey
    public let client: RatchetClientProtocol
    @objc public let crypto = VirgilCrypto()
    @objc public let privateKeyProvider: PrivateKeyProvider

    public init(identityPrivateKey: VirgilPrivateKey, accessTokenProvider: AccessTokenProvider, client: RatchetClientProtocol, privateKeyProvider: PrivateKeyProvider) {
        self.identityPrivateKey = identityPrivateKey
        self.accessTokenProvider = accessTokenProvider
        self.client = client
        self.privateKeyProvider = privateKeyProvider

        super.init()
    }
    
    @objc open func startNewSessionAsSender(receiverCard: Card) throws -> SecureSession {
        let tokenContext = TokenContext(service: "ratchet", operation: "get")
        let getTokenOperation = OperationUtils.makeGetTokenOperation(
            tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
        
        // FIXME
        let token = try getTokenOperation.startSync().getResult()
        
        // TODO: checkExistingSessionOnStart

        let publicKeySet = try self.client.getPublicKeySet(forRecipientIdentity: receiverCard.identity, token: token.stringRepresentation())
        
        guard let identityPublicKey = receiverCard.publicKey as? VirgilPublicKey else {
            throw NSError()
        }
        
        guard CUtils.extractRawPublicKey(self.crypto.exportPublicKey(identityPublicKey)) == publicKeySet.identityPublicKey else {
            throw NSError()
        }
        
        // FIXME
        guard self.crypto.verifySignature(publicKeySet.longtermPublicKey.signature, of: publicKeySet.longtermPublicKey.publicKey, with: identityPublicKey) else {
            throw NSError()
        }
        
        if publicKeySet.onetimePublicKey == nil {
            // TODO: Weak session warning
        }
        
        let privateKeyData = CUtils.extractRawPrivateKey(self.crypto.exportPrivateKey(self.identityPrivateKey))
        
        return try SecureSession(senderIdentityPrivateKey: privateKeyData, receiverIdentityPublicKey: publicKeySet.identityPublicKey, receivedLongTermPublicKey: publicKeySet.longtermPublicKey.publicKey, receiverOneTimePublicKey: publicKeySet.onetimePublicKey)
    }
    
    @objc public func startNewSessionAsReceiver(senderCard: Card, message: Data) throws -> SecureSession {
        guard let senderIdentityPublicKey = senderCard.publicKey as? VirgilPublicKey else {
            throw NSError()
        }
        
        return try SecureSession(privateKeyProvider: self.privateKeyProvider, receiverIdentityPrivateKey: self.identityPrivateKey, senderIdentityPublicKey: CUtils.extractRawPublicKey(self.crypto.exportPublicKey(senderIdentityPublicKey)), message: message)
    }
}
