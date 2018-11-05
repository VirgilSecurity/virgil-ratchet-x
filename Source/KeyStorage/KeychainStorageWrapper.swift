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

/// Declares error types and codes for KeychainStorageWrapper
///
/// - errorConvertingKeychainEntry: Invalid Keychain entry
@objc(VSKKeychainStorageWrapperError) public enum KeychainStorageWrapperError: Int, Error {
    case errorConvertingKeychainEntry = 0
}

public final class KeychainStorageWrapper {
    public let keychainStorage: KeychainStorageProtocol
    public let identity: String?
    public let prefix: String?

    internal init(identity: String? = nil, prefix: String? = nil, keychainStorage: KeychainStorageProtocol) {
        self.identity = identity
        self.prefix = prefix
        self.keychainStorage = keychainStorage
    }

    private func keychainPrefix() -> String {
        let identityStr: String
        if let identity = self.identity {
            identityStr = "IDENTITY=\(identity)."
        }
        else {
            identityStr = ""
        }
        
        let prefixStr: String
        if let prefix = self.prefix {
            prefixStr = "PREFIX=\(prefix)."
        }
        else {
            prefixStr = ""
        }
        
        return "VIRGIL.\(identityStr)\(prefixStr)"
    }

    private func keychainName(fromEntryName entryName: String) -> String {
        return "\(self.keychainPrefix())\(entryName)"
    }

    private func entryName(fromKeychainName keychainName: String) -> String? {
        guard keychainName.hasPrefix(self.keychainPrefix()) else {
            return nil
        }

        return keychainName.replacingOccurrences(of: self.keychainPrefix(), with: "")
    }
}

extension KeychainStorageWrapper {
    private func mapKeychainEntry(_ keychainEntry: KeychainEntry) -> KeychainEntry? {
        guard let entryName = self.entryName(fromKeychainName: keychainEntry.name) else {
            return nil
        }

        return KeychainEntry(data: keychainEntry.data, name: entryName, meta: keychainEntry.meta,
                             creationDate: keychainEntry.creationDate,
                             modificationDate: keychainEntry.modificationDate)
    }

    private func mapKeychainEntries(_ keychainEntries: [KeychainEntry]) -> [KeychainEntry] {
        return keychainEntries.compactMap {
            return self.mapKeychainEntry($0)
        }
    }

    public func store(data: Data, withName name: String, meta: [String: String]?) throws -> KeychainEntry {
        let keychainName = self.keychainName(fromEntryName: name)

        let keychainEntry = try self.keychainStorage.store(data: data, withName: keychainName, meta: meta)
        
        guard let entry = self.mapKeychainEntry(keychainEntry) else {
            throw KeychainStorageWrapperError.errorConvertingKeychainEntry
        }
        
        return entry
    }

    public func updateEntry(withName name: String, data: Data, meta: [String: String]?) throws {
        let keychainName = self.keychainName(fromEntryName: name)

        try self.keychainStorage.updateEntry(withName: keychainName, data: data, meta: meta)
    }

    public func retrieveEntry(withName name: String) throws -> KeychainEntry {
        let keychainName = self.keychainName(fromEntryName: name)

        let keychainEntry = try self.keychainStorage.retrieveEntry(withName: keychainName)

        guard let entry = self.mapKeychainEntry(keychainEntry) else {
            throw KeychainStorageWrapperError.errorConvertingKeychainEntry
        }

        return entry
    }

    public func retrieveAllEntries() throws -> [KeychainEntry] {
        return self.mapKeychainEntries(try self.keychainStorage.retrieveAllEntries())
    }

    public func deleteEntry(withName name: String) throws {
        let keychainName = self.keychainName(fromEntryName: name)

        try self.keychainStorage.deleteEntry(withName: keychainName)
    }

    public func existsEntry(withName name: String) throws -> Bool {
        let keychainName = self.keychainName(fromEntryName: name)

        return try self.keychainStorage.existsEntry(withName: keychainName)
    }
}

extension KeychainStorageWrapper: KeychainStorageProtocol { }
