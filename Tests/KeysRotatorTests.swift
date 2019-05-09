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

import Foundation
import XCTest
import VirgilSDK
import VirgilCrypto
import VirgilCryptoRatchet
@testable import VirgilSDKRatchet

class KeysRotatorTests: XCTestCase {
    private let keyId = RatchetKeyId()
    private let crypto = try! VirgilCrypto()
    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func compareCloudAndStorage(userStore: RamClient.UserStore, longTermStorage: RamLongTermKeysStorage, oneTimeStorage: RamOneTimeKeysStorage) -> Bool {
        
        do {
            if let longTermKey = userStore.longTermPublicKey?.publicKey {
                let keyId = try self.keyId.computePublicKeyId(publicKey: longTermKey)
                
                guard try longTermStorage.retrieveKey(withId: keyId).identifier == keyId else {
                    return false
                }
            }
            
            let storedOneTimeKeysIds = Set<Data>(try oneTimeStorage.retrieveAllKeys().map { $0.identifier })
            
            let cloudOneTimeKeysIds = Set<Data>(try userStore.oneTimePublicKeys.map {
                try self.keyId.computePublicKeyId(publicKey: $0)
            })
            
            guard storedOneTimeKeysIds == cloudOneTimeKeysIds else {
                return false
            }
        }
        catch {
            return false
        }
        
        return true
    }
    
    private func initialize() throws -> (CardManager, AccessTokenProvider, JwtGenerator, String, VirgilPrivateKey, Card) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = try! VirgilCrypto()
        let identityKeyPair = try! crypto.generateKeyPair(ofType: .ed25519)
        
        let identity = NSUUID().uuidString
        
        let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
        
        let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(virgilCrypto: crypto), appId: testConfig.AppId, ttl: 10050)
        
        let tokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            completion(try! generator.generateToken(identity: identity), nil)
        })
        
        let cardVerifier = VirgilCardVerifier(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto))!
        cardVerifier.verifyVirgilSignature = false
        
        let cardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto), accessTokenProvider: tokenProvider, cardVerifier: cardVerifier)
        cardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let cardManager = CardManager(params: cardManagerParams)
        
        let card = try cardManager.publishCard(privateKey: identityKeyPair.privateKey, publicKey: identityKeyPair.publicKey).startSync().getResult()
        
        return (cardManager, tokenProvider, generator, identity, identityKeyPair.privateKey, card)
    }
    
    private func rotate(rotator: KeysRotator, tokenProvider: AccessTokenProvider) throws -> RotationLog {
        let getTokenOperation = VirgilSDK.OperationUtils.makeGetTokenOperation(tokenContext: TokenContext(service: "ratchet", operation: "rotate"), accessTokenProvider: tokenProvider)
        
        let rotateOperation = rotator.rotateKeysOperation()
        rotateOperation.addDependency(getTokenOperation)
        
        let queue = OperationQueue()
        queue.addOperations([getTokenOperation, rotateOperation], waitUntilFinished: true)
        
        return try rotateOperation.result!.getResult()
    }
    
    func test1__rotate__empty_storage__should_create_keys() {
        do {
            let (cardManager, tokenProvider, _, identity, privateKey, card) = try self.initialize()
            
            let numberOfOneTimeKeys = 5
            
            let fakeLongTermKeysStorage = RamLongTermKeysStorage(db: [:])
            let fakeOneTimeKeysStorage = RamOneTimeKeysStorage(db: [:])
            let fakeClient = RamClient(cardManager: cardManager)
            
            let rotator = KeysRotator(crypto: crypto, identityPrivateKey: privateKey, identityCardId: card.identifier, orphanedOneTimeKeyTtl: 100, longTermKeyTtl: 100, outdatedLongTermKeyTtl: 100, desiredNumberOfOneTimeKeys: numberOfOneTimeKeys, longTermKeysStorage: fakeLongTermKeysStorage, oneTimeKeysStorage: fakeOneTimeKeysStorage, client: fakeClient)
            
            let log = try self.rotate(rotator: rotator, tokenProvider: tokenProvider)
            
            XCTAssert(log.longTermKeysRelevant == 1)
            XCTAssert(log.longTermKeysAdded == 1)
            XCTAssert(log.longTermKeysDeleted == 0)
            XCTAssert(log.longTermKeysMarkedOutdated == 0)
            XCTAssert(log.longTermKeysOutdated == 0)
            
            XCTAssert(log.oneTimeKeysRelevant == numberOfOneTimeKeys)
            XCTAssert(log.oneTimeKeysAdded == numberOfOneTimeKeys)
            XCTAssert(log.oneTimeKeysDeleted == 0)
            XCTAssert(log.oneTimeKeysMarkedOrphaned == 0)
            XCTAssert(log.oneTimeKeysOrphaned == 0)
            
            XCTAssert(fakeOneTimeKeysStorage.db.count == numberOfOneTimeKeys)
            XCTAssert(fakeLongTermKeysStorage.db.count == 1)
            XCTAssert(fakeClient.users.count == 1)
            
            let user = fakeClient.users.first!
            XCTAssert(user.key == identity)
            
            XCTAssert(self.compareCloudAndStorage(userStore: user.value, longTermStorage: fakeLongTermKeysStorage, oneTimeStorage: fakeOneTimeKeysStorage))
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test2__rotate__old_long_term_key__should_recreate_key() {
        do {
            let (cardManager, tokenProvider, _, identity, privateKey, card) = try self.initialize()
            
            let numberOfOneTimeKeys = 5
            
            let fakeLongTermKeysStorage = RamLongTermKeysStorage(db: [:])
            let fakeOneTimeKeysStorage = RamOneTimeKeysStorage(db: [:])
            let fakeClient = RamClient(cardManager: cardManager)
            
            let rotator = KeysRotator(crypto: crypto, identityPrivateKey: privateKey, identityCardId: card.identifier, orphanedOneTimeKeyTtl: 100, longTermKeyTtl: 5, outdatedLongTermKeyTtl: 2, desiredNumberOfOneTimeKeys: numberOfOneTimeKeys, longTermKeysStorage: fakeLongTermKeysStorage, oneTimeKeysStorage: fakeOneTimeKeysStorage, client: fakeClient)
            
            _ = try self.rotate(rotator: rotator, tokenProvider: tokenProvider)
            
            sleep(6)
            
            let log1 = try self.rotate(rotator: rotator, tokenProvider: tokenProvider)
            
            XCTAssert(log1.longTermKeysRelevant == 1)
            XCTAssert(log1.longTermKeysAdded == 1)
            XCTAssert(log1.longTermKeysDeleted == 0)
            XCTAssert(log1.longTermKeysMarkedOutdated == 1)
            XCTAssert(log1.longTermKeysOutdated == 1)
            
            XCTAssert(fakeOneTimeKeysStorage.db.count == numberOfOneTimeKeys)
            XCTAssert(fakeLongTermKeysStorage.db.count == 2)
            XCTAssert(fakeClient.users.count == 1)
            
            let user = fakeClient.users.first!
            XCTAssert(user.key == identity)
            
            XCTAssert(self.compareCloudAndStorage(userStore: user.value, longTermStorage: fakeLongTermKeysStorage, oneTimeStorage: fakeOneTimeKeysStorage))
            
            sleep(2)
            
            let log2 = try self.rotate(rotator: rotator, tokenProvider: tokenProvider)
            
            XCTAssert(log2.longTermKeysRelevant == 1)
            XCTAssert(log2.longTermKeysAdded == 0)
            XCTAssert(log2.longTermKeysDeleted == 1)
            XCTAssert(log2.longTermKeysMarkedOutdated == 0)
            XCTAssert(log2.longTermKeysOutdated == 0)
            
            XCTAssert(fakeOneTimeKeysStorage.db.count == numberOfOneTimeKeys)
            XCTAssert(fakeLongTermKeysStorage.db.count == 1)
            XCTAssert(fakeClient.users.count == 1)
            
            XCTAssert(self.compareCloudAndStorage(userStore: user.value, longTermStorage: fakeLongTermKeysStorage, oneTimeStorage: fakeOneTimeKeysStorage))
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test3__rotate__used_one_time_key___should_recreate_key() {
        do {
            let (cardManager, tokenProvider, generator, identity, privateKey, card) = try self.initialize()
            
            let numberOfOneTimeKeys = 5
            
            let fakeLongTermKeysStorage = RamLongTermKeysStorage(db: [:])
            let fakeOneTimeKeysStorage = RamOneTimeKeysStorage(db: [:])
            let fakeClient = RamClient(cardManager: cardManager)
            
            let rotator = KeysRotator(crypto: crypto, identityPrivateKey: privateKey, identityCardId: card.identifier, orphanedOneTimeKeyTtl: 5, longTermKeyTtl: 100, outdatedLongTermKeyTtl: 100, desiredNumberOfOneTimeKeys: numberOfOneTimeKeys, longTermKeysStorage: fakeLongTermKeysStorage, oneTimeKeysStorage: fakeOneTimeKeysStorage, client: fakeClient)
            
            _ = try self.rotate(rotator: rotator, tokenProvider: tokenProvider)
            
            let token = try generator.generateToken(identity: identity)
            
            _ = try fakeClient.getPublicKeySet(forRecipientIdentity: token.identity(), token: token.stringRepresentation())
            
            let log1 = try self.rotate(rotator: rotator, tokenProvider: tokenProvider)
            
            XCTAssert(log1.oneTimeKeysRelevant == numberOfOneTimeKeys)
            XCTAssert(log1.oneTimeKeysAdded == 1)
            XCTAssert(log1.oneTimeKeysDeleted == 0)
            XCTAssert(log1.oneTimeKeysMarkedOrphaned == 1)
            XCTAssert(log1.oneTimeKeysOrphaned == 1)
            
            XCTAssert(fakeOneTimeKeysStorage.db.count == numberOfOneTimeKeys + 1)
            XCTAssert(fakeLongTermKeysStorage.db.count == 1)
            
            sleep(6)
            
            let log2 = try self.rotate(rotator: rotator, tokenProvider: tokenProvider)
            
            XCTAssert(log2.oneTimeKeysRelevant == numberOfOneTimeKeys)
            XCTAssert(log2.oneTimeKeysAdded == 0)
            XCTAssert(log2.oneTimeKeysDeleted == 1)
            XCTAssert(log2.oneTimeKeysMarkedOrphaned == 0)
            XCTAssert(log2.oneTimeKeysOrphaned == 0)
            
            XCTAssert(fakeOneTimeKeysStorage.db.count == numberOfOneTimeKeys)
            XCTAssert(fakeLongTermKeysStorage.db.count == 1)
            XCTAssert(fakeClient.users.count == 1)
            
            let user = fakeClient.users.first!
            XCTAssert(user.key == identity)
            
            XCTAssert(self.compareCloudAndStorage(userStore: user.value, longTermStorage: fakeLongTermKeysStorage, oneTimeStorage: fakeOneTimeKeysStorage))
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
}
