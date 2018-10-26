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
import VSCRatchet
import VirgilCryptoApiImpl

@objc(VSRSecureSession) public final class SecureSession: NSObject {
    @objc public let crypto = VirgilCrypto()
    @objc public let sessionStorage: SessionStorage
    
    private let ratchetSession: OpaquePointer
    @objc public let participantIdentity: String
    
    private static func createSession() throws -> OpaquePointer {
        let kdfInfo = vscr_ratchet_kdf_info_new()!
        
        // FIXME
        let kdfRootInfo = "kdfRootInfo"
        let kdfRatchetInfo = "kdfRatchetInfo"
        kdfInfo.pointee.root_info = vsc_buffer_new_with_capacity(kdfRootInfo.count)
        try CUtils.copy(data: kdfRootInfo.data(using: .utf8)!, buffer: kdfInfo.pointee.root_info)
        kdfInfo.pointee.ratchet_info = vsc_buffer_new_with_capacity(kdfRatchetInfo.count)
        try CUtils.copy(data: kdfRatchetInfo.data(using: .utf8)!, buffer: kdfInfo.pointee.ratchet_info)
        
        let kdfCipherInfo = "kdfCipherInfo"
        let ratchetCipher = vscr_ratchet_cipher_new()!
        ratchetCipher.pointee.kdf_info = vsc_buffer_new_with_capacity(kdfCipherInfo.count)
        try CUtils.copy(data: kdfCipherInfo.data(using: .utf8)!, buffer: ratchetCipher.pointee.kdf_info)
        
        let ratchet = vscr_ratchet_new()!
        vscr_ratchet_take_rng(ratchet, vscr_virgil_ratchet_fake_rng_new())
        vscr_ratchet_take_kdf_info(ratchet, kdfInfo)
        vscr_ratchet_take_cipher(ratchet, ratchetCipher)
        
        // FIXME
        let ratchetSession = vscr_ratchet_session_new()!
        vscr_ratchet_session_take_rng(ratchetSession, vscr_virgil_ratchet_fake_rng_new())
        vscr_ratchet_session_take_ratchet(ratchetSession, ratchet)
        
        return ratchetSession
    }
    
    // FIXME
    // As receiver
    internal init(privateKeyProvider: PrivateKeyProvider, sessionStorage: SessionStorage, participantIdentity: String, receiverIdentityPrivateKey: VirgilPrivateKey, senderIdentityPublicKey: Data, message: Data) throws {
        self.sessionStorage = sessionStorage
        self.participantIdentity = participantIdentity
        
        self.ratchetSession = try SecureSession.createSession()
        
        var status: vscr_error_t = vscr_SUCCESS
        
        // FIXME
        guard let ratchetMessage = vscr_ratchet_message_deserialize(CUtils.bindForRead(data: message), nil) else {
            throw NSError()
        }
        
        guard ratchetMessage.pointee.type == vscr_ratchet_message_TYPE_PREKEY else {
            throw NSError()
        }
        
        // FIXME
        guard let prekeyMessage = vscr_ratchet_prekey_message_deserialize(vsc_buffer_data(ratchetMessage.pointee.message), nil) else {
            throw NSError()
        }
        
        // FIXME
        guard let regularMessage = vscr_ratchet_regular_message_deserialize(vsc_buffer_data(prekeyMessage.pointee.message), nil) else {
            throw NSError()
        }
        
        let senderIdentityPublicKeyBuf = vsc_buffer_new_with_capacity(32)!
        
        try CUtils.copy(data: senderIdentityPublicKey, buffer: senderIdentityPublicKeyBuf)
        
        let receiverLongTermPublicKey = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: vsc_buffer_bytes(prekeyMessage.pointee.receiver_long_term_key)!), count: vsc_buffer_len(prekeyMessage.pointee.receiver_long_term_key), deallocator: Data.Deallocator.none)
        
        // CHECK one time is zero
        let receiverOneTimePublicKey = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: vsc_buffer_bytes(prekeyMessage.pointee.receiver_one_time_key)!), count: vsc_buffer_len(prekeyMessage.pointee.receiver_one_time_key), deallocator: Data.Deallocator.none)
        
        let receiverLongTermPrivateKey = try privateKeyProvider.getPrivateKey(withId: receiverLongTermPublicKey)
        let receiverOneTimePrivateKey = try privateKeyProvider.getPrivateKey(withId: receiverOneTimePublicKey)
        
        let receiverIdentityPrivateKeyBuf = vsc_buffer_new_with_capacity(32)!
        let receiverLongTermPrivateKeyBuf = vsc_buffer_new_with_capacity(32)!
        let receiverOneTimePrivateKeyBuf = vsc_buffer_new_with_capacity(32)!
        
        try CUtils.copy(data: CUtils.extractRawPrivateKey(self.crypto.exportPrivateKey(receiverIdentityPrivateKey)), buffer: receiverIdentityPrivateKeyBuf)
        try CUtils.copy(data: receiverLongTermPrivateKey, buffer: receiverLongTermPrivateKeyBuf)
        try CUtils.copy(data: receiverOneTimePrivateKey, buffer: receiverOneTimePrivateKeyBuf)
        
        status = vscr_ratchet_session_respond(self.ratchetSession, senderIdentityPublicKeyBuf, prekeyMessage.pointee.sender_ephemeral_key, regularMessage.pointee.public_key, receiverIdentityPrivateKeyBuf, receiverLongTermPrivateKeyBuf, receiverOneTimePrivateKeyBuf)
        
        vsc_buffer_delete(senderIdentityPublicKeyBuf)
        
        vsc_buffer_delete(receiverIdentityPrivateKeyBuf)
        vsc_buffer_delete(receiverLongTermPrivateKeyBuf)
        vsc_buffer_delete(receiverOneTimePrivateKeyBuf)
        
        vscr_ratchet_regular_message_delete(regularMessage)
        vscr_ratchet_prekey_message_delete(prekeyMessage)
        
        guard status == vscr_SUCCESS else {
            throw NSError()
        }
        
        super.init()
    }
    
    // As sender
    internal init(sessionStorage: SessionStorage, participantIdentity: String, senderIdentityPrivateKey: Data, receiverIdentityPublicKey: Data, receivedLongTermPublicKey: Data, receiverOneTimePublicKey: Data?) throws {
        self.sessionStorage = sessionStorage
        self.participantIdentity = participantIdentity
        
        self.ratchetSession = try SecureSession.createSession()
        
        let senderIdentityPrivateKeyBuf = vsc_buffer_new_with_capacity(32)!
        let receiverIdentityPublicKeyBuf = vsc_buffer_new_with_capacity(32)!
        let receivedLongTermPublicKeyBuf = vsc_buffer_new_with_capacity(32)!
        let receiverOneTimePublicKeyBuf: OpaquePointer?
        
        // FIXME
        try CUtils.copy(data: senderIdentityPrivateKey, buffer: senderIdentityPrivateKeyBuf)
        try CUtils.copy(data: receiverIdentityPublicKey, buffer: receiverIdentityPublicKeyBuf)
        try CUtils.copy(data: receivedLongTermPublicKey, buffer: receivedLongTermPublicKeyBuf)
        
        if let receiverOneTimePublicKey = receiverOneTimePublicKey {
            receiverOneTimePublicKeyBuf = vsc_buffer_new_with_capacity(32)!
            try CUtils.copy(data: receiverOneTimePublicKey, buffer: receiverOneTimePublicKeyBuf!)
        }
        else {
            receiverOneTimePublicKeyBuf = nil
        }
        
        let status = vscr_ratchet_session_initiate(self.ratchetSession, senderIdentityPrivateKeyBuf, receiverIdentityPublicKeyBuf, receivedLongTermPublicKeyBuf, receiverOneTimePublicKeyBuf)
        
        vsc_buffer_delete(senderIdentityPrivateKeyBuf);
        vsc_buffer_delete(receiverIdentityPublicKeyBuf);
        vsc_buffer_delete(receivedLongTermPublicKeyBuf);
        vsc_buffer_delete(receiverOneTimePublicKeyBuf);
        
        guard status == vscr_SUCCESS else {
            throw NSError()
        }
        
        super.init()
    }
    
    public func encrypt(message: String) throws -> Data {
        guard let msgData = message.data(using: .utf8) else {
            throw NSError()
        }
        
        let buffLen = vscr_ratchet_session_encrypt_len(self.ratchetSession, msgData.count)
        
        let buffer = vsc_buffer_new()!
        
        var cipherText = CUtils.bindForWrite(capacity: buffLen, buffer: buffer)
        
        let status = vscr_ratchet_session_encrypt(self.ratchetSession, CUtils.bindForRead(data: msgData), buffer)
        
        let outputLen = vsc_buffer_len(buffer)
        
        vsc_buffer_delete(buffer)
        
        cipherText.count = outputLen
        
        guard status == vscr_SUCCESS else {
            throw NSError()
        }
        
        try self.sessionStorage.storeSession(self)
        
        return cipherText
    }
    
    public func decrypt(message: UnsafePointer<vscr_ratchet_message_t>) throws -> String {
        let buffLen = vscr_ratchet_session_decrypt_len(self.ratchetSession, message)
        
        let buff = vsc_buffer_new()!
        
        var buffer = CUtils.bindForWrite(capacity: buffLen, buffer: buff)
        
        let status = vscr_ratchet_session_decrypt(self.ratchetSession, message, buff)
        buffer.count = vsc_buffer_len(buff)
        vsc_buffer_delete(buff)
        
        guard status == vscr_SUCCESS else {
            throw NSError()
        }
        
        try self.sessionStorage.storeSession(self)
        
        // FIXME
        return String(data: buffer, encoding: .utf8)!
    }
    
    deinit {
        vscr_ratchet_session_delete(self.ratchetSession)
    }
}
