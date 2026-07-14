import Foundation

@objc public protocol AuthsiaBridgeXPCProtocol {
    func ping(_ reply: @escaping (Data?, NSError?) -> Void)
    func status(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func unlock(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func lock(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func getOTP(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func getPassword(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func getAPIKey(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func getCertificate(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func getNote(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func getSSH(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func list(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func auditVerify(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func exportAccounts(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func addItem(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func updateItem(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func deleteItem(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
}

@objc public protocol AuthsiaBridgeApprovalCallbackProtocol {
    func requestApproval(prompt: String, command: String, itemLabel: String?, field: String?, reply: @escaping (Bool) -> Void)
}
