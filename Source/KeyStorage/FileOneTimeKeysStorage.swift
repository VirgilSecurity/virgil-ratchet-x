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

// TODO: Make thread-safe
@objc(VSRFileOneTimeKeysStorage) open class FileOneTimeKeysStorage: NSObject, OneTimeKeysStorage {
    @objc public let identity: String
    private var oneTimeKeys: OneTimeKeys?
    private let fileManager = FileManager()
    
    private struct OneTimeKeys: Codable {
        var oneTimeKeys: [OneTimeKey]
    }
    
    @objc public init(identity: String) {
        self.identity = identity
        
        super.init()
    }
    
    private func createTempDirUrl() throws -> URL {
        var dirUrl = try self.fileManager.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: try self.createFileUrl(), create: true)
        
        dirUrl.appendPathComponent("VIRGIL-RATCHET")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
        }
        
        dirUrl.appendPathComponent("\(self.identity)")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
        }
        
        return dirUrl
    }
    
    private func createSuppDirUrl() throws -> URL {
        var dirUrl = try self.fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        
        dirUrl.appendPathComponent("VIRGIL-RATCHET")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
        }
        
        dirUrl.appendPathComponent("\(self.identity)")
        
        if !self.fileManager.fileExists(atPath: dirUrl.path) {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
        }
        
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        
        try dirUrl.setResourceValues(values)
        
        return dirUrl
    }
    
    private func createFileUrl() throws -> URL {
        let dirUrl = try self.createSuppDirUrl()
        
        let fileUrl = dirUrl.appendingPathComponent("KEYS")
        
        if !self.fileManager.fileExists(atPath: fileUrl.path) {
            self.fileManager.createFile(atPath: fileUrl.path, contents: nil, attributes: nil)
        }
        
        return fileUrl
    }
    
    private func createTempFileUrl() throws -> URL {
        let dirUrl = try self.createTempDirUrl()
        
        return dirUrl.appendingPathComponent("TEMP")
    }

    public func startInteraction() {
        guard self.oneTimeKeys == nil else {
            return
        }
        
        let fileUrl = try! self.createFileUrl()
        
        // TODO: Add encryption
        let data = try! Data(contentsOf: fileUrl)
        
        if data.isEmpty {
            self.oneTimeKeys = OneTimeKeys(oneTimeKeys: [])
        }
        else {
            self.oneTimeKeys = try! PropertyListDecoder().decode(OneTimeKeys.self, from: data)
        }
    }
    
    public func stopInteraction() {
        let tempFileUrl = try! self.createTempFileUrl()
        let fileUrl = try! self.createFileUrl()
        
        let data = try! PropertyListEncoder().encode(self.oneTimeKeys)
        
        try? self.fileManager.removeItem(at: tempFileUrl)
        self.fileManager.createFile(atPath: tempFileUrl.path, contents: data, attributes: nil)
        
        try! self.fileManager.replaceItem(at: fileUrl, withItemAt: tempFileUrl, backupItemName: "BACKUP", options: [], resultingItemURL: nil)
        
        self.oneTimeKeys = nil
    }
    
    public func storeKey(_ key: Data, withId id: Data) throws -> OneTimeKey {
        guard var oneTimeKeys = self.oneTimeKeys else {
            throw NSError()
        }
        
        guard !oneTimeKeys.oneTimeKeys.map({ $0.identifier }).contains(id) else {
            throw NSError()
        }
        
        let oneTimeKey = OneTimeKey(identifier: id, key: key, orphanedFrom: nil)
        oneTimeKeys.oneTimeKeys.append(oneTimeKey)
        self.oneTimeKeys = oneTimeKeys
        
        return oneTimeKey
    }
    
    public func retrieveKey(withId id: Data) throws -> OneTimeKey {
        guard let oneTimeKeys = self.oneTimeKeys else {
            throw NSError()
        }
        
        guard let oneTimeKey = oneTimeKeys.oneTimeKeys.first(where: { $0.identifier == id } ) else {
            throw NSError()
        }
        
        return oneTimeKey
    }
    
    public func deleteKey(withId id: Data) throws {
        guard var oneTimeKeys = self.oneTimeKeys else {
            throw NSError()
        }
        
        guard let index = oneTimeKeys.oneTimeKeys.firstIndex(where: { $0.identifier == id }) else {
            throw NSError()
        }
        
        oneTimeKeys.oneTimeKeys.remove(at: index)
        self.oneTimeKeys = oneTimeKeys
    }
    
    public func retrieveAllKeys() throws -> [OneTimeKey] {
        guard let oneTimeKeys = self.oneTimeKeys else {
            throw NSError()
        }
        
        return oneTimeKeys.oneTimeKeys
    }
    
    public func markKeyOrphaned(startingFrom date: Date, keyId: Data) throws {
        guard var oneTimeKeys = self.oneTimeKeys else {
            throw NSError()
        }
        
        guard let index = oneTimeKeys.oneTimeKeys.firstIndex(where: { $0.identifier == keyId }) else {
            throw NSError()
        }
        
        let oneTimeKey = oneTimeKeys.oneTimeKeys[index]
        
        guard oneTimeKey.orphanedFrom == nil else {
            throw NSError()
        }
        
        oneTimeKeys.oneTimeKeys[index] = OneTimeKey(identifier: oneTimeKey.identifier, key: oneTimeKey.key, orphanedFrom: date)
        self.oneTimeKeys = oneTimeKeys
    }
}
