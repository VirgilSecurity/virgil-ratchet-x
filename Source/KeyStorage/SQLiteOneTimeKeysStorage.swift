//
// Copyright (C) 2015-2021 Virgil Security Inc.
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
import VirgilCrypto
import VirgilSDK

/// Represents error of `SQLiteCardStorage`
///
/// - inconsistentDb: Storage turned into inconsistency state
/// - keyNotFound: Key not found
@objc(VSRSQLiteCardStorageError) public enum SQLiteCardStorageError: Int, LocalizedError {
    case inconsistentDb = 1
    case keyNotFound = 2

    /// Human-readable localized description
    public var errorDescription: String? {
        switch self {
        case .inconsistentDb:
            return "Storage turned into inconsistency state"
        case .keyNotFound:
            return "Key not found"
        }
    }
}

/// SQLiteOneTimeKeysStorage
public class SQLiteOneTimeKeysStorage: OneTimeKeysStorage {
    private enum Statements: String {
        case createTable = """
        CREATE TABLE IF NOT EXISTS OneTimeKeys(
        id TEXT UNIQUE NOT NULL,
        orphaned_from INTEGER,
        key BLOB NOT NULL);
        """

        case createIndexId = "CREATE UNIQUE INDEX IF NOT EXISTS id_index ON OneTimeKeys(id);"

        case createIndexOrhpaned = "CREATE INDEX IF NOT EXISTS orphaned_from_index ON OneTimeKeys(orphaned_from);"

        case insertKey = """
        INSERT OR REPLACE INTO OneTimeKeys (id, orphaned_from, key) VALUES (?, ?, ?);
        """

        case markOrphaned = "UPDATE OneTimeKeys SET orphaned_from = ? WHERE id = ?;"

        case selectKeyById = "SELECT key, orphaned_from FROM OneTimeKeys WHERE id = ?;"

        case selectAllKeyInfo = "SELECT id, orphaned_from FROM OneTimeKeys;"

        case deleteKeyById = "DELETE FROM OneTimeKeys WHERE id = ?;"

        case deleteAllKeys = "DELETE FROM OneTimeKeys;"
    }

    private let db: SQLiteDB
    private let crypto: VirgilCrypto
    private let identityKeyPair: VirgilKeyPair

    internal var dbPath: String {
        return self.db.path
    }

    /// Init
    /// - Parameters:
    ///   - appGroup: appGroup
    ///   - identity: identity
    ///   - crypto: crypto
    ///   - identityKeyPair: identityKeyPair
    /// - Throws: SQLiteError
    @objc public init(appGroup: String?,
                      identity: String,
                      crypto: VirgilCrypto,
                      identityKeyPair: VirgilKeyPair) throws {
        self.crypto = crypto
        self.identityKeyPair = identityKeyPair

        self.db = try SQLiteDB(appGroup: appGroup,
                               prefix: "VIRGIL_SQLITE",
                               userIdentifier: identity,
                               name: "oneTimeKeys.sqlite")

        try self.db.executeNoResult(statement: Statements.createTable.rawValue)
        try self.db.executeNoResult(statement: Statements.createIndexId.rawValue)
        try self.db.executeNoResult(statement: Statements.createIndexOrhpaned.rawValue)
    }

    public func storeKey(_ key: Data, withId id: Data) throws {
        let stmt = try self.db.generateStmt(statement: Statements.insertKey.rawValue)

        let encryptedKey = try self.crypto.authEncrypt(key,
                                                       with: self.identityKeyPair.privateKey,
                                                       for: [self.identityKeyPair.publicKey])

        try self.db.bindIn(stmt: stmt,
                           value1: id.base64EncodedString(),
                           value2: Int32(-1),
                           value3: encryptedKey)

        try self.db.executeNoResult(statement: stmt)
    }

    private static func convertDateToInt(date: Date) -> Int32 {
        return Int32(date.timeIntervalSince1970)
    }

    private static func convertIntToDate(int: Int32) -> Date? {
        return int == -1 ? nil : Date(timeIntervalSince1970: Double(int))
    }

    public func retrieveKey(withId id: Data) throws -> OneTimeKey {
        let stmt = try self.db.generateStmt(statement: Statements.selectKeyById.rawValue)

        try self.db.bindIn(stmt: stmt, value: id.base64EncodedString())

        guard try self.db.executeStep(statement: stmt) else {
            throw SQLiteCardStorageError.keyNotFound
        }

        let keyData: Data?
        let orphanedInt32: Int32?

        (keyData, orphanedInt32) = try self.db.bindOut(stmt: stmt)

        guard let key = keyData, let orphanedInt32l = orphanedInt32 else {
            throw SQLiteCardStorageError.inconsistentDb
        }

        let decryptedKey = try self.crypto.authDecrypt(key,
                                                       with: self.identityKeyPair.privateKey,
                                                       usingOneOf: [self.identityKeyPair.publicKey])

        return OneTimeKey(identifier: id, key: decryptedKey, orphanedFrom: Self.convertIntToDate(int: orphanedInt32l))
    }

    public func deleteKey(withId id: Data) throws {
        let stmt = try self.db.generateStmt(statement: Statements.deleteKeyById.rawValue)

        try self.db.bindIn(stmt: stmt, value: id.base64EncodedString())

        try self.db.executeNoResult(statement: stmt)
    }

    public func retrieveAllKeys() throws -> [OneTimeKeyInfo] {
        let stmt = try self.db.generateStmt(statement: Statements.selectAllKeyInfo.rawValue)

        var result: [OneTimeKeyInfo] = []

        while try self.db.executeStep(statement: stmt) {
            let keyIdBase64: String?
            let orphanedInt32: Int32?

            (keyIdBase64, orphanedInt32) = try self.db.bindOut(stmt: stmt)

            guard let keyIdBase64w = keyIdBase64,
                let keyId = Data(base64Encoded: keyIdBase64w),
                let orphanedInt32l = orphanedInt32 else {
                throw SQLiteCardStorageError.inconsistentDb
            }

            result.append(OneTimeKeyInfo(identifier: keyId, orphanedFrom: Self.convertIntToDate(int: orphanedInt32l)))
        }

        return result
    }

    public func markKeyOrphaned(startingFrom date: Date, keyId: Data) throws {
        let stmt = try self.db.generateStmt(statement: Statements.markOrphaned.rawValue)

        try self.db.bindIn(stmt: stmt, value1: Self.convertDateToInt(date: date), value2: keyId.base64EncodedString())

        try self.db.executeNoResult(statement: stmt)
    }

    public func reset() throws {
        let stmt = try self.db.generateStmt(statement: Statements.deleteAllKeys.rawValue)

        try self.db.executeNoResult(statement: stmt)
    }
}
