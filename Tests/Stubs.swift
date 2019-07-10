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

import VirgilSDK
import VirgilCrypto
import VirgilCryptoRatchet
@testable import VirgilSDKRatchet

class RamSessionStorage: SessionStorage {
    private var db: [String: SecureSession] = [:]
    
    func storeSession(_ session: SecureSession) throws {
        self.db[session.participantIdentity] = session
    }
    
    func retrieveSession(participantIdentity: String, name: String) -> SecureSession? {
        return self.db[participantIdentity]
    }
    
    func deleteSession(participantIdentity: String, name: String?) throws {
        guard self.db.removeValue(forKey: participantIdentity) != nil else {
            throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
    }
    
    func reset() throws {
        self.db = [:]
    }
}

class RamGroupSessionStorage: GroupSessionStorage {
    private var db: [Data: SecureGroupSession] = [:]
    
    func storeSession(_ session: SecureGroupSession) throws {
        self.db[session.identifier] = session
    }
    
    func retrieveSession(identifier: Data) -> SecureGroupSession? {
        return self.db[identifier]
    }
    
    func deleteSession(identifier: Data) throws {
        guard self.db.removeValue(forKey: identifier) != nil else {
            throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
    }
    
    func reset() throws {
        self.db = [:]
    }
}

class RamLongTermKeysStorage: LongTermKeysStorage {
    var db: [Data: LongTermKey] = [:]
    
    init(db: [Data: LongTermKey]) {
        self.db = db
    }

    func storeKey(_ key: Data, withId id: Data) throws -> LongTermKey {
        let longTermKey = LongTermKey(identifier: id, key: key, creationDate: Date(), outdatedFrom: nil)
        self.db[id] = longTermKey
        return longTermKey
    }
    
    func retrieveKey(withId id: Data) throws -> LongTermKey {
        guard let key = self.db[id] else {
            throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
        
        return key
    }
    
    func deleteKey(withId id: Data) throws {
        guard self.db.removeValue(forKey: id) != nil else {
            throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
    }
    
    func retrieveAllKeys() throws -> [LongTermKey] {
        return [LongTermKey](self.db.values)
    }
    
    func markKeyOutdated(startingFrom date: Date, keyId: Data) throws {
        guard let key = self.db[keyId] else {
            throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
        
        self.db[keyId] = LongTermKey(identifier: keyId, key: key.key, creationDate: key.creationDate, outdatedFrom: date)
    }
    
    func reset() throws {
        self.db = [:]
    }
}

class RamOneTimeKeysStorage: OneTimeKeysStorage {
    var db: [Data: OneTimeKey] = [:]
    
    init(db: [Data: OneTimeKey]) {
        self.db = db
    }
    
    func startInteraction() throws { }
    
    func stopInteraction() throws { }
    
    func storeKey(_ key: Data, withId id: Data) throws -> OneTimeKey {
        let oneTimeKey = OneTimeKey(identifier: id, key: key, orphanedFrom: nil)
        self.db[id] = oneTimeKey
        return oneTimeKey
    }
    
    func retrieveKey(withId id: Data) throws -> OneTimeKey {
        guard let key = self.db[id] else {
            throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
        
        return key
    }
    
    func deleteKey(withId id: Data) throws {
        guard self.db.removeValue(forKey: id) != nil else {
            throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
    }
    
    func retrieveAllKeys() throws -> [OneTimeKey] {
        return [OneTimeKey](self.db.values)
    }
    
    func markKeyOrphaned(startingFrom date: Date, keyId: Data) throws {
        guard let key = self.db[keyId] else {
            throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
        
        self.db[keyId] = OneTimeKey(identifier: keyId, key: key.key, orphanedFrom: date)
    }
    
    func reset() throws {
        self.db = [:]
    }
}

class RamClient: RatchetClientProtocol {
    func getMultiplePublicKeysSets(forRecipientsIdentities identities: [String]) throws -> [IdentityPublicKeySet] {
        throw NSError(domain: "Stub", code: -1, userInfo: nil)
    }
    
    struct UserEntry {
        var identityPublicKey: (VirgilPublicKey, Data)?
        var longTermPublicKey: SignedPublicKey?
        var oneTimePublicKeys: Set<Data> = []
    }
    
    class Storage {
        var users: [String: UserEntry] = [:]
    }
    
    private let keyId = RatchetKeyId()
    private let cardManager: CardManager
    private let crypto = try! VirgilCrypto()
    private let identity: String
    let storage: Storage
    
    init(identity: String, storage: Storage, cardManager: CardManager) {
        self.identity = identity
        self.cardManager = cardManager
        self.storage = storage
    }
    
    func uploadPublicKeys(identityCardId: String?, longTermPublicKey: SignedPublicKey?, oneTimePublicKeys: [Data]) throws {
        var userStore = self.storage.users[self.identity] ?? UserEntry()
        
        let publicKey: VirgilPublicKey
        if let identityCardId = identityCardId {
            let card = try self.cardManager.getCard(withId: identityCardId).startSync().get()
            publicKey = card.publicKey
            userStore.identityPublicKey = (publicKey, try self.crypto.exportPublicKey(publicKey))
        }
        else {
            guard let existingIdentityPublicKey = userStore.identityPublicKey else {
                throw NSError(domain: "Stub", code: -1, userInfo: nil)
            }
            
            publicKey = existingIdentityPublicKey.0
        }
        
        if let longTermPublicKey = longTermPublicKey {
            guard try crypto.verifySignature(longTermPublicKey.signature, of: longTermPublicKey.publicKey, with: publicKey) else {
                throw NSError(domain: "Stub", code: -1, userInfo: nil)
            }
            
            userStore.longTermPublicKey = longTermPublicKey
        }
        else {
            guard userStore.longTermPublicKey != nil else {
                throw NSError(domain: "Stub", code: -1, userInfo: nil)
            }
        }
        
        if !oneTimePublicKeys.isEmpty {
            let newKeysSet = Set<Data>(oneTimePublicKeys)
            
            guard userStore.oneTimePublicKeys.intersection(newKeysSet).isEmpty else {
                throw NSError(domain: "Stub", code: -1, userInfo: nil)
            }
            
            userStore.oneTimePublicKeys.formUnion(newKeysSet)
        }
        
        self.storage.users[self.identity] = userStore
    }
    
    func validatePublicKeys(longTermKeyId: Data?, oneTimeKeysIds: [Data]) throws -> ValidatePublicKeysResponse {
        let userStore = self.storage.users[self.identity] ?? UserEntry()
        
        let usedLongTermKeyId: Data?
        
        if let longTermKeyId = longTermKeyId,
            let storedLongTermPublicKey = userStore.longTermPublicKey?.publicKey,
            try self.keyId.computePublicKeyId(publicKey: storedLongTermPublicKey) == longTermKeyId {
                usedLongTermKeyId = nil
        }
        else {
            usedLongTermKeyId = longTermKeyId
        }
        
        let usedOneTimeKeysIds: [Data] = Array<Data>(Set<Data>(oneTimeKeysIds).subtracting(userStore.oneTimePublicKeys.map { try! self.keyId.computePublicKeyId(publicKey: $0) }))
        
        return ValidatePublicKeysResponse(usedLongTermKeyId: usedLongTermKeyId, usedOneTimeKeysIds: usedOneTimeKeysIds)
    }
    
    func getPublicKeySet(forRecipientIdentity identity: String) throws -> PublicKeySet {
        var userStore = self.storage.users[identity] ?? UserEntry()
        
        guard let identityPublicKey = userStore.identityPublicKey?.1,
            let longTermPublicKey = userStore.longTermPublicKey else {
                throw NSError(domain: "Stub", code: -1, userInfo: nil)
        }
        
        let oneTimePublicKey: Data?
        if let randomOneTimePublicKey = userStore.oneTimePublicKeys.randomElement() {
            oneTimePublicKey = randomOneTimePublicKey
            userStore.oneTimePublicKeys.remove(randomOneTimePublicKey)
            
            self.storage.users[identity] = userStore
        }
        else {
            oneTimePublicKey = nil
        }
        
        return PublicKeySet(identityPublicKey: identityPublicKey, longTermPublicKey: longTermPublicKey, oneTimePublicKey: oneTimePublicKey)
    }
    
    func deleteKeysEntity() throws {
        self.storage.users = [:]
    }
}

class FakeKeysRotator: KeysRotatorProtocol {
    func rotateKeysOperation() -> GenericOperation<RotationLog> {
        return CallbackOperation { _, completion in
            completion(RotationLog(), nil)
        }
    }
}

class RamCardClient: CardClientProtocol {
    func revokeCard(withId cardId: String) throws {
        throw NSError(domain: "Stub", code: -1, userInfo: nil)
    }
    
    let crypto = try! VirgilCrypto()
    private var cards: [String: RawSignedModel] = [:]
    
    func getCard(withId cardId: String) throws -> GetCardResponse {
        if let model = self.cards[cardId] {
            return GetCardResponse(rawCard: model, isOutdated: false)
        }
        
        throw NSError(domain: "Stub", code: -1, userInfo: nil)
    }
    
    func publishCard(model: RawSignedModel) throws -> RawSignedModel {
        let cardId = self.crypto.computeHash(for: model.contentSnapshot, using: .sha512).subdata(in: 0..<32).hexEncodedString()
        
        self.cards[cardId] = model
        
        return model
    }
    
    func searchCards(identity: String) throws -> [RawSignedModel] {
        throw NSError(domain: "Stub", code: -1, userInfo: nil)
    }
    
    func searchCards(identities: [String]) throws -> [RawSignedModel] {
        throw NSError(domain: "Stub", code: -1, userInfo: nil)
    }
}

class PositiveCardVerifier: CardVerifier {
    func verifyCard(_ card: Card) -> Bool {
        return true
    }
}
