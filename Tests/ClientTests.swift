//
// Copyright (C) 2015-2020 Virgil Security Inc.
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
import VirgilSDK
import VirgilCrypto
import VirgilCryptoRatchet
import VirgilCryptoFoundation
@testable import VirgilSDKRatchet

class ClientTests: XCTestCase {
    private func initialize() throws -> (String, VirgilPrivateKey, Card, RatchetClient) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = try! VirgilCrypto()
        let identityKeyPair = try! crypto.generateKeyPair(ofType: .ed25519)
        
        let identity = NSUUID().uuidString
        
        let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
        
        let generator = try! JwtGenerator(apiKey: privateKey,
                                          apiPublicKeyIdentifier: testConfig.ApiKeyId,
                                          crypto: crypto,
                                          appId: testConfig.AppId,
                                          ttl: 10050)
        
        let tokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            completion(try! generator.generateToken(identity: identity), nil)
        })
        
        let client = RatchetClient(accessTokenProvider: tokenProvider, serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let cardVerifier = VirgilCardVerifier(crypto: crypto)!
        cardVerifier.verifyVirgilSignature = false
        
        let cardManagerParams = CardManagerParams(crypto: crypto, accessTokenProvider: tokenProvider, cardVerifier: cardVerifier)
        cardManagerParams.cardClient = CardClient(accessTokenProvider: tokenProvider, serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let cardManager = CardManager(params: cardManagerParams)
        
        let card = try cardManager.publishCard(privateKey: identityKeyPair.privateKey, publicKey: identityKeyPair.publicKey, identity: identity).startSync().get()
        
        return (identity, identityKeyPair.privateKey, card, client)
    }
    
    func test1__full_cycle__long_term_key__should_succeed() {
        do {
            let (identity, privateKey, card, client) = try self.initialize()
            
            let crypto = try VirgilCrypto()
            
            let longTermKey = try crypto.generateKeyPair(ofType: .curve25519)
            
            let longTermPublicKey = try crypto.exportPublicKey(longTermKey.publicKey)
            let signature = try crypto.generateSignature(of: longTermPublicKey, using: privateKey)
            
            let signedLongTermKey = SignedPublicKey(publicKey: longTermPublicKey, signature: signature)
            
            try client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [])
            
            let response1 = try client.validatePublicKeys(longTermKeyId: longTermKey.identifier, oneTimeKeysIds: [])
            
            XCTAssert(response1.usedLongTermKeyId == nil)
            
            let response2 = try client.getPublicKeySet(forRecipientIdentity: identity)
            
            XCTAssert(response2.longTermPublicKey.publicKey == signedLongTermKey.publicKey)
            XCTAssert(response2.longTermPublicKey.signature == signedLongTermKey.signature)
            XCTAssert(response2.oneTimePublicKey == nil)
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test2__full_cycle__all_keys__should_succeed() {
        do {
            let (identity, privateKey, card, client) = try self.initialize()
            
            let crypto = try VirgilCrypto()
            
            let longTermKey = try crypto.generateKeyPair(ofType: .curve25519)
            let oneTimeKey1 = try crypto.generateKeyPair(ofType: .curve25519)
            let oneTimeKey2 = try crypto.generateKeyPair(ofType: .curve25519)
        
            let longTermPublicKey = try crypto.exportPublicKey(longTermKey.publicKey)
            let oneTimePublicKey1 = try crypto.exportPublicKey(oneTimeKey1.publicKey)
            let oneTimePublicKey2 = try crypto.exportPublicKey(oneTimeKey2.publicKey)
            let signature = try crypto.generateSignature(of: longTermPublicKey, using: privateKey)
            
            let signedLongTermKey = SignedPublicKey(publicKey: longTermPublicKey, signature: signature)
            
            try client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [oneTimePublicKey1, oneTimePublicKey2])
            
            let response1 = try client.validatePublicKeys(longTermKeyId: longTermKey.identifier, oneTimeKeysIds: [oneTimeKey1.identifier, oneTimeKey2.identifier])
            
            XCTAssert(response1.usedLongTermKeyId == nil)
            XCTAssert(response1.usedOneTimeKeysIds.isEmpty)
            
            let response2 = try client.getPublicKeySet(forRecipientIdentity: identity)
            
            XCTAssert(response2.longTermPublicKey.publicKey == signedLongTermKey.publicKey)
            XCTAssert(response2.longTermPublicKey.signature == signedLongTermKey.signature)
            
            let usedKeyId: Data
            if (response2.oneTimePublicKey == oneTimePublicKey1) {
                usedKeyId = oneTimeKey1.identifier
            }
            else if (response2.oneTimePublicKey == oneTimePublicKey2) {
                usedKeyId = oneTimeKey2.identifier
            }
            else {
                usedKeyId = Data()
                XCTFail()
            }
            
            let response3 = try client.validatePublicKeys(longTermKeyId: longTermKey.identifier, oneTimeKeysIds: [oneTimeKey1.identifier, oneTimeKey2.identifier])
            
            XCTAssert(response3.usedLongTermKeyId == nil)
            XCTAssert(response3.usedOneTimeKeysIds.count == 1)
            XCTAssert(response3.usedOneTimeKeysIds[0] == usedKeyId)
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test3__full_cycle__multiple_identities__should_succeed() {
        do {
            let crypto = try VirgilCrypto()
            
            struct Entry {
                var identity: String
                var client: RatchetClient
                var identityPublicKey: Data
                var longTermKey: Data
                var longTermKeySignature: Data
                var oneTimeKey1: Data
                var oneTimeKey2: Data
            }
            
            var entries: [Entry] = []
            
            for _ in 0..<10 {
                let (identity, privateKey, card, client) = try self.initialize()
                
                let longTermKey = try crypto.generateKeyPair(ofType: .curve25519)
                let oneTimeKey1 = try crypto.exportPublicKey(try crypto.generateKeyPair(ofType: .curve25519).publicKey)
                let oneTimeKey2 = try crypto.exportPublicKey(try crypto.generateKeyPair(ofType: .curve25519).publicKey)
                
                let longTermPublicKey = try crypto.exportPublicKey(longTermKey.publicKey)
                let signature = try crypto.generateSignature(of: longTermPublicKey, using: privateKey)
                
                let signedLongTermKey = SignedPublicKey(publicKey: longTermPublicKey, signature: signature)
                
                try client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [oneTimeKey1, oneTimeKey2])
                
                let entry = Entry(identity: identity,
                                  client: client,
                                  identityPublicKey: try crypto.exportPublicKey(crypto.extractPublicKey(from: privateKey)),
                                  longTermKey: longTermPublicKey,
                                  longTermKeySignature: signature,
                                  oneTimeKey1: oneTimeKey1,
                                  oneTimeKey2: oneTimeKey2)
                
                entries.append(entry)
            }
            
            let response = try entries.last!.client.getMultiplePublicKeysSets(forRecipientsIdentities: entries.map { $0.identity })
            
            XCTAssert(response.count == entries.count)
            
            for entry in entries {
                let cloudEntry = response.first { $0.identity == entry.identity }!
                
                XCTAssert(cloudEntry.identityPublicKey == entry.identityPublicKey)
                XCTAssert(cloudEntry.longTermPublicKey.publicKey == entry.longTermKey)
                XCTAssert(cloudEntry.longTermPublicKey.signature == entry.longTermKeySignature)
                XCTAssert(cloudEntry.oneTimePublicKey! == entry.oneTimeKey1 || cloudEntry.oneTimePublicKey! == entry.oneTimeKey2)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test4__reset__all_keys__should_succeed() {
        do {
            let (identity, privateKey, card, client) = try self.initialize()
            
            let crypto = try VirgilCrypto()
            
            let longTermKey = try crypto.generateKeyPair(ofType: .curve25519)
            let oneTimeKey = try crypto.exportPublicKey(try crypto.generateKeyPair(ofType: .curve25519).publicKey)
            
            let longTermPublicKey = try crypto.exportPublicKey(longTermKey.publicKey)
            let signature = try crypto.generateSignature(of: longTermPublicKey, using: privateKey)
            
            let signedLongTermKey = SignedPublicKey(publicKey: longTermPublicKey, signature: signature)
            
            try client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [oneTimeKey])
            
            try client.deleteKeysEntity()
            
            do {
                _ = try client.getPublicKeySet(forRecipientIdentity: identity)
                XCTFail()
            }
            catch { }
            
            try client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [oneTimeKey])
            
            let response = try client.getPublicKeySet(forRecipientIdentity: identity)
            
            XCTAssert(response.longTermPublicKey.publicKey == signedLongTermKey.publicKey)
            XCTAssert(response.longTermPublicKey.signature == signedLongTermKey.signature)
            XCTAssert (response.oneTimePublicKey == oneTimeKey)
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
}
