//
// Copyright (C) 2015-2019 Virgil Security Inc.
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

import XCTest
import VirgilSDKRatchet

class Utils {
    static func encryptDecrypt100Times(senderSession: SecureSession, receiverSession: SecureSession) throws {
        for _ in 0..<100 {
            try autoreleasepool {
                let sender: SecureSession
                let receiver: SecureSession
                
                if Bool.random() {
                    sender = senderSession
                    receiver = receiverSession
                }
                else {
                    sender = receiverSession
                    receiver = senderSession
                }
                
                let plainText = UUID().uuidString
                
                let message = try sender.encrypt(string: plainText)
                
                let decryptedMessage = try receiver.decryptString(from: message)
                
                XCTAssert(decryptedMessage == plainText)
            }
        }
    }
    
    static func encryptDecrypt100Times(groupSessions: [SecureGroupSession]) throws {
        for _ in 0..<100 {
            let senderNum = Int.random(in: 0..<groupSessions.count)
            
            let sender = groupSessions[senderNum]
            
            let plainText = UUID().uuidString
            
            let message = try sender.encrypt(string: plainText)
            
            for i in 0..<groupSessions.count {
                if i == senderNum {
                    continue
                }
                
                let receiver = groupSessions[i]
                
                let decryptedMessage = try receiver.decryptString(from: message, senderCardId: sender.myIdentifier)
                
                XCTAssert(decryptedMessage == plainText)
            }
        }
    }
    
    static func encryptDecrypt100TimesRestored(secureChats: [SecureChat], sessionId: Data) throws {
        for _ in 0..<100 {
            let senderNum = Int.random(in: 0..<secureChats.count)
            
            let sender = secureChats[senderNum].existingGroupSession(sessionId: sessionId)!
            
            let plainText = UUID().uuidString
            
            let message = try sender.encrypt(string: plainText)
            
            try secureChats[senderNum].storeGroupSession(sender)
            
            for i in 0..<secureChats.count {
                if i == senderNum {
                    continue
                }
                
                let receiver = secureChats[i].existingGroupSession(sessionId: sessionId)!
                
                let decryptedMessage = try receiver.decryptString(from: message, senderCardId: sender.myIdentifier)
                
                XCTAssert(decryptedMessage == plainText)
                
                try secureChats[i].storeGroupSession(receiver)
            }
        }
    }
    
    static func encryptDecrypt100TimesRestored(senderSecureChat: SecureChat, senderIdentity: String, receiverSecureChat: SecureChat, receiverIdentity: String) throws {
        for _ in 0..<100 {
            let sender: SecureSession
            let receiver: SecureSession
            
            if Bool.random() {
                sender = senderSecureChat.existingSession(withParticipantIdentity: receiverIdentity)!
                receiver = receiverSecureChat.existingSession(withParticipantIdentity: senderIdentity)!
            }
            else {
                sender = receiverSecureChat.existingSession(withParticipantIdentity: senderIdentity)!
                receiver = senderSecureChat.existingSession(withParticipantIdentity: receiverIdentity)!
            }
            
            let plainText = UUID().uuidString
            
            let message = try sender.encrypt(string: plainText)
            
            let decryptedMessage = try receiver.decryptString(from: message)
            
            XCTAssert(decryptedMessage == plainText)
            
            try senderSecureChat.storeSession(sender)
            try receiverSecureChat.storeSession(receiver)
        }
    }
}
