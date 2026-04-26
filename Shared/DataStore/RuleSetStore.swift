//
//  RuleSetStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Combine

private let logger = AnywhereLogger(category: "RuleSetStore")

@MainActor
class RuleSetStore: ObservableObject {
    static let shared = RuleSetStore()

    struct RuleSet: Identifiable, Equatable {
        let id: String   // built-in: name, custom: UUID string
        let name: String
        var assignedConfigurationId: String?  // nil = default, "DIRECT" = bypass, "REJECT" = block, UUID string = proxy
        var isCustom: Bool = false
    }
    
    struct CustomRuleSet: Codable, Identifiable, Equatable {
        let id: UUID
        var name: String
        var rules: [DomainRule]
        var remoteSubscriptionURL: String?
        var remoteUpdateIntervalHours: Int
        var lastRemoteUpdate: Date?

        init(
            name: String,
            rules: [DomainRule] = [],
            remoteSubscriptionURL: String? = nil,
            remoteUpdateIntervalHours: Int = 24,
            lastRemoteUpdate: Date? = nil
        ) {
            self.id = UUID()
            self.name = name
            self.rules = rules
            self.remoteSubscriptionURL = remoteSubscriptionURL
            self.remoteUpdateIntervalHours = max(1, remoteUpdateIntervalHours)
            self.lastRemoteUpdate = lastRemoteUpdate
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decode(UUID.self, forKey: .id)
            name = try container.decode(String.self, forKey: .name)
            rules = try container.decodeIfPresent([DomainRule].self, forKey: .rules) ?? []
            remoteSubscriptionURL = try container.decodeIfPresent(String.self, forKey: .remoteSubscriptionURL)
            let hours = try container.decodeIfPresent(Int.self, forKey: .remoteUpdateIntervalHours) ?? 24
            remoteUpdateIntervalHours = max(1, hours)
            lastRemoteUpdate = try container.decodeIfPresent(Date.self, forKey: .lastRemoteUpdate)
        }
    }

    @Published private(set) var ruleSets: [RuleSet] = []
    @Published private(set) var customRuleSets: [CustomRuleSet] = []

    var adBlockRuleSet: RuleSet? {
        ruleSets.first(where: { $0.name == "ADBlock" })
    }
    var builtInServiceRuleSets: [RuleSetStore.RuleSet] {
        ruleSets.filter { $0.name != "Direct" && $0.name != "ADBlock" }
    }

    /// Bundled ruleset names: Direct + supported services + ADBlock.
    private static let builtIn: [String] = {
        ["Direct"] + serviceCatalog.supportedServices + ["ADBlock"]
    }()

    private static let serviceCatalog = ServiceCatalog.load()

    private static let defaultAssignments: [String: String] = ["Direct": "DIRECT"]

    private init() {
        let assignments = AWCore.getRuleSetAssignments()

        // Load custom rulesets
        if let data = AWCore.getCustomRuleSetsData(),
           let decoded = try? JSONDecoder().decode([CustomRuleSet].self, from: data) {
            customRuleSets = decoded
        }

        rebuildRuleSets(assignments: assignments)
    }

    private func rebuildRuleSets(assignments: [String: String]? = nil) {
        let assignmentsDict = assignments ?? AWCore.getRuleSetAssignments()

        var sets = Self.builtIn.map { name in
            RuleSet(id: name, name: name, assignedConfigurationId: assignmentsDict[name] ?? Self.defaultAssignments[name])
        }

        // Insert custom rule sets before ADBlock so that ADBlock retains
        // highest priority.  Desired trie-overwrite order (lowest → highest):
        // Country Bypass → Direct → Services → User/Custom → ADBlock
        let insertionIndex = sets.firstIndex(where: { $0.id == "ADBlock" }) ?? sets.endIndex
        for (offset, custom) in customRuleSets.enumerated() {
            let id = custom.id.uuidString
            sets.insert(RuleSet(
                id: id,
                name: custom.name,
                assignedConfigurationId: assignmentsDict[id],
                isCustom: true
            ), at: insertionIndex + offset)
        }

        ruleSets = sets
    }

    // MARK: - Assignment

    func updateAssignment(_ ruleSet: RuleSet, configurationId: String?) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSet.id }) else { return }
        ruleSets[index].assignedConfigurationId = configurationId
        saveAssignments()
    }

    func resetAssignments() {
        for builtInServiceRuleSet in builtInServiceRuleSets {
            guard let index = ruleSets.firstIndex(where: { $0.id == builtInServiceRuleSet.id }) else { continue }
            ruleSets[index].assignedConfigurationId = nil
        }
        for customRuleSet in customRuleSets {
            guard let index = ruleSets.firstIndex(where: { $0.id == customRuleSet.id.uuidString }) else { continue }
            ruleSets[index].assignedConfigurationId = nil
        }
        saveAssignments()
    }

    /// Resets any rule set assignments that reference configuration UUIDs not in `availableConfigIds`.
    /// Returns the names of affected rule sets, or empty if nothing changed.
    func clearOrphanedAssignments(availableConfigIds: Set<String>) -> [String] {
        var affected: [String] = []
        for (index, ruleSet) in ruleSets.enumerated() {
            guard let assignedId = ruleSet.assignedConfigurationId,
                  assignedId != "DIRECT",
                  assignedId != "REJECT",
                  !availableConfigIds.contains(assignedId) else { continue }
            ruleSets[index].assignedConfigurationId = nil
            affected.append(ruleSet.name)
        }
        if !affected.isEmpty {
            saveAssignments()
        }
        return affected
    }

    // MARK: - Custom Rule Set CRUD

    func addCustomRuleSet(name: String) -> CustomRuleSet {
        let ruleSet = CustomRuleSet(name: name)
        customRuleSets.append(ruleSet)
        saveCustomRuleSets()
        rebuildRuleSets()
        return ruleSet
    }

    func removeCustomRuleSet(_ id: UUID) {
        customRuleSets.removeAll { $0.id == id }
        saveCustomRuleSets()

        // Remove assignment for this custom ruleset
        var assignments = AWCore.getRuleSetAssignments()
        assignments.removeValue(forKey: id.uuidString)
        AWCore.setRuleSetAssignments(assignments)

        rebuildRuleSets()
    }

    func updateCustomRuleSet(_ id: UUID, name: String? = nil, rules: [DomainRule]? = nil) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == id }) else { return }
        if let name { customRuleSets[index].name = name }
        if let rules { customRuleSets[index].rules = rules }
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    func updateCustomRuleSetRemoteSubscription(_ id: UUID, url: String?) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == id }) else { return }
        let trimmed = url?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        customRuleSets[index].remoteSubscriptionURL = trimmed.isEmpty ? nil : trimmed
        if trimmed.isEmpty {
            customRuleSets[index].lastRemoteUpdate = nil
        }
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    func addRule(to customRuleSetId: UUID, rule: DomainRule) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == customRuleSetId }) else { return }
        customRuleSets[index].rules.append(rule)
        saveCustomRuleSets()
    }

    func addRules(to customRuleSetId: UUID, rules: [DomainRule]) {
        guard !rules.isEmpty,
              let index = customRuleSets.firstIndex(where: { $0.id == customRuleSetId }) else { return }
        customRuleSets[index].rules.append(contentsOf: rules)
        saveCustomRuleSets()
    }

    func removeRules(from customRuleSetId: UUID, at indices: [Int]) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == customRuleSetId }) else { return }
        for i in indices.sorted().reversed() {
            customRuleSets[index].rules.remove(at: i)
        }
        saveCustomRuleSets()
    }

    func customRuleSet(for id: UUID) -> CustomRuleSet? {
        customRuleSets.first { $0.id == id }
    }

    /// Pulls all remote custom rule set subscriptions if their update interval has elapsed.
    /// Returns `true` when at least one rule set changed.
    func refreshRemoteRuleSetsIfNeeded() async -> Bool {
        guard !customRuleSets.isEmpty else { return false }
        var changed = false

        for custom in customRuleSets {
            guard let urlString = custom.remoteSubscriptionURL,
                  !urlString.isEmpty else { continue }

            let interval = TimeInterval(custom.remoteUpdateIntervalHours * 3600)
            if let last = custom.lastRemoteUpdate,
               Date().timeIntervalSince(last) < interval {
                continue
            }

            guard let url = URL(string: urlString) else {
                logger.warning("[RuleSetStore] Invalid custom rules subscription URL: \(urlString)")
                continue
            }

            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    logger.warning("[RuleSetStore] Remote custom rules update failed: HTTP \(http.statusCode) (\(custom.name))")
                    continue
                }
                guard let body = String(data: data, encoding: .utf8) else {
                    logger.warning("[RuleSetStore] Remote custom rules update failed: invalid text encoding (\(custom.name))")
                    continue
                }
                let parsed = Self.parseRules(body)
                guard !parsed.isEmpty else {
                    logger.warning("[RuleSetStore] Remote custom rules update yielded 0 rules (\(custom.name))")
                    continue
                }

                guard let index = customRuleSets.firstIndex(where: { $0.id == custom.id }) else { continue }
                customRuleSets[index].rules = parsed
                customRuleSets[index].lastRemoteUpdate = Date()
                changed = true
            } catch {
                logger.warning("[RuleSetStore] Remote custom rules update failed (\(custom.name)): \(error.localizedDescription)")
            }
        }

        if changed {
            saveCustomRuleSets()
            rebuildRuleSets()
        }
        return changed
    }

    // MARK: - Rules

    /// Loads rules for a given built-in rule set name. Thread-safe – no instance state accessed.
    /// All built-in rules are stored in the bundled Rules.db SQLite database.
    static func loadRules(for name: String) -> [DomainRule] {
        if name != "Direct" && name != "ADBlock" {
            return serviceCatalog.rules(for: name)
        }
        return RulesDatabase.shared.loadRules(for: name)
    }

    // MARK: - App Group Sync

    func syncToAppGroup(configurations: [ProxyConfiguration], serializeConfiguration: @escaping @Sendable (ProxyConfiguration) -> [String: Any]) async {
        // Snapshot main-actor state
        let snapshot = ruleSets
        let customSnapshot = customRuleSets
        let configs = configurations

        await Task.detached {
            var routingRules: [[String: Any]] = []
            var configurationsDict: [String: Any] = [:]

            for ruleSet in snapshot {
                guard let assignedId = ruleSet.assignedConfigurationId else { continue }

                // Load rules: custom rulesets use captured data, built-in use database
                let domainRules: [DomainRule]
                if ruleSet.isCustom,
                   let customId = UUID(uuidString: ruleSet.id),
                   let custom = customSnapshot.first(where: { $0.id == customId }) {
                    domainRules = custom.rules
                } else {
                    domainRules = await Self.loadRules(for: ruleSet.name)
                }
                guard !domainRules.isEmpty else { continue }

                let domainRulesArray: [[String: Any]] = domainRules.compactMap {
                    switch $0.type {
                    case .domainSuffix, .domainKeyword:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .ipCIDR, .ipCIDR6:
                        return nil
                    }
                }
                let ipRulesArray: [[String: Any]] = domainRules.compactMap {
                    switch $0.type {
                    case .ipCIDR, .ipCIDR6:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .domainSuffix, .domainKeyword:
                        return nil
                    }
                }
                var ruleEntry: [String: Any] = ["domainRules": domainRulesArray]
                if !ipRulesArray.isEmpty {
                    ruleEntry["ipRules"] = ipRulesArray
                }

                if assignedId == "DIRECT" {
                    ruleEntry["action"] = "direct"
                } else if assignedId == "REJECT" {
                    ruleEntry["action"] = "reject"
                } else if let configurationUUID = UUID(uuidString: assignedId),
                          let configuration = configs.first(where: { $0.id == configurationUUID }) {
                    ruleEntry["action"] = "proxy"
                    ruleEntry["configId"] = assignedId
                    var serialized = serializeConfiguration(configuration)
                    if let resolvedIP = VPNViewModel.resolveServerAddress(configuration.serverAddress) {
                        serialized["resolvedIP"] = resolvedIP
                    }
                    configurationsDict[assignedId] = serialized
                } else {
                    continue
                }

                routingRules.append(ruleEntry)
            }

            // Fetch bypass country rules
            var bypassRules: [[String: Any]] = []
            let countryCode = AWCore.getBypassCountryCode()
            if !countryCode.isEmpty {
                let rules = await CountryBypassCatalog.shared.rules(for: countryCode)
                bypassRules = rules.map {
                    ["type": $0.type.rawValue, "value": $0.value]
                }
            }

            var routing: [String: Any] = ["rules": routingRules, "configs": configurationsDict]
            if !bypassRules.isEmpty {
                routing["bypassRules"] = bypassRules
            }

            if let data = try? JSONSerialization.data(withJSONObject: routing) {
                AWCore.setRoutingData(data)
            }

            AWCore.notifyRoutingChanged()
        }.value
    }

    // MARK: - Persistence

    private func saveAssignments() {
        let dict = Dictionary(uniqueKeysWithValues: ruleSets.compactMap { rs in
            rs.assignedConfigurationId.map { (rs.id, $0) }
        })
        AWCore.setRuleSetAssignments(dict)
    }

    private func saveCustomRuleSets() {
        if let data = try? JSONEncoder().encode(customRuleSets) {
            AWCore.setCustomRuleSetsData(data)
        }
    }

    private static func parseRules(_ text: String) -> [DomainRule] {
        text
            .components(separatedBy: .newlines)
            .compactMap { parseRuleLine($0) }
    }

    private static func parseRuleLine(_ line: String) -> DomainRule? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.hasPrefix("#") || trimmed.hasPrefix("//") { return nil }

        guard let commaIndex = trimmed.firstIndex(of: ",") else { return nil }
        let prefix = trimmed[trimmed.startIndex..<commaIndex].trimmingCharacters(in: .whitespaces)
        let value = trimmed[trimmed.index(after: commaIndex)...].trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty, let typeInt = Int(prefix), let type = DomainRuleType(rawValue: typeInt) else {
            return nil
        }

        switch type {
        case .ipCIDR:
            return DomainRule(type: type, value: value.contains("/") ? value : value + "/32")
        case .ipCIDR6:
            return DomainRule(type: type, value: value.contains("/") ? value : value + "/128")
        case .domainSuffix, .domainKeyword:
            return DomainRule(type: type, value: value)
        }
    }
}
