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
import VirgilCryptoRatchet
import VirgilCryptoApiImpl

@objc(VSRSecureSession) public final class SecureSession: NSObject {
    @objc public let crypto = VirgilCrypto()
    @objc public let sessionStorage: SessionStorage
    
    private let ratchetSession: RatchetSession
    @objc public let participantIdentity: String
    
    internal init(sessionStorage: SessionStorage,
                  participantIdentity: String,
                  receiverIdentityPrivateKey: VirgilPrivateKey,
                  receiverLongTermPrivateKey: LongTermKey,
                  receiverOneTimePrivateKey: OneTimeKey?,
                  senderIdentityPublicKey: Data,
                  ratchetMessage: RatchetMessage) throws {
        self.sessionStorage = sessionStorage
        self.participantIdentity = participantIdentity
        
        let ratchetSession = RatchetSession()
        ratchetSession.setupDefaults()
        
        try ratchetSession.respond(senderIdentityPublicKey: senderIdentityPublicKey, receiverIdentityPrivateKey: CUtils.extractRawPrivateKey(self.crypto.exportPrivateKey(receiverIdentityPrivateKey)), receiverLongTermPrivateKey: receiverLongTermPrivateKey.key, receiverOneTimePrivateKey: receiverOneTimePrivateKey?.key ?? Data(), message: ratchetMessage)
        
        self.ratchetSession = ratchetSession
        
        super.init()
    }
    
    // As sender
    internal init(sessionStorage: SessionStorage,
                  participantIdentity: String,
                  senderIdentityPrivateKey: Data,
                  receiverIdentityPublicKey: Data,
                  receiverLongTermPublicKey: Data,
                  receiverOneTimePublicKey: Data?) throws {
        self.sessionStorage = sessionStorage
        self.participantIdentity = participantIdentity
        
        let ratchetSession = RatchetSession()
        ratchetSession.setupDefaults()
        
        try ratchetSession.initiate(senderIdentityPrivateKey: senderIdentityPrivateKey, receiverIdentityPublicKey: receiverIdentityPublicKey, receiverLongTermPublicKey: receiverLongTermPublicKey, receiverOneTimePublicKey: receiverOneTimePublicKey ?? Data())
        
        self.ratchetSession = ratchetSession
        
        super.init()
    }
    
    public func encrypt(message: String) throws -> RatchetMessage {
        guard let msgData = message.data(using: .utf8) else {
            throw NSError()
        }
        
        let errCtx = ErrorCtx()
        let msg = self.ratchetSession.encrypt(plainText: msgData, errCtx: errCtx)
        
        try errCtx.error()
        
        try self.sessionStorage.storeSession(self)
        
        return msg
    }
    
    public func decrypt(message: RatchetMessage) throws -> String {
        let data = try self.ratchetSession.decrypt(message: message)
        
        try self.sessionStorage.storeSession(self)
        
        return String(data: data, encoding: .utf8)!
    }
}
