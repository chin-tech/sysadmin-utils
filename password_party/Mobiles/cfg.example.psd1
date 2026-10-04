@{
    # Data files contain literal values. The module appends the current username
    # to nfsHomeRoot to derive NfsHome; omit NfsHome unless supplying a literal path.
    nfsHomeRoot = 'C:\Temp'
    MobileRoot = '\\nas\home\.mobiles'
    SshKeyName = 'deployer'
    CertName = 'MobileDeployer'
    GpoID = '{00000000-0000-0000-0000-000000000000}' # Replace with the actual GPO ID.
    # Supply deployment secrets through -ConfigOverride or a protected local cfg.psd1.
}
