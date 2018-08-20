# Carubbi.Security
A simple symmetric cryptography helper

## 1. Symmetrict Cryptography

Example:
```CSharp
 var crypt = new SymmetricCrypt(SymmetricCryptProvider.TripleDES) { Key = "Your Salt Key" };
 var encrypedData = crypt.Encrypt("plain text");
 var decrypedData = crypt.Encrypt(encrypedData);
```

## 2. Protect a config section

Example:

### 2.1 To allow your app read a protected section, declare the provider in your config file
```XML
<?xml version="1.0"?>
<configuration>
  <configProtectedData >
    <providers>
      <clear />
      <add keyContainerName="KeyContainerName.txt"
      name="CarubbiEncryptionProvider"
      type="Carubbi.Security.TripleDESProtectedConfigurationProvider, Carubbi.Security" />
      </providers>
  </configProtectedData >
</configuration>
```

### 2.2 To protect your section by the first time, run this code in an app with the same configuration above:
```CSharp
TripleDESProtectedConfigurationProvider provider = new TripleDESProtectedConfigurationProvider();
provider.CreateKey(keyName);

if (ConfigurationManager.GetSection("connectionStrings") is ConfigurationSection section)
{
    section.SectionInformation.ProtectSection("CarubbiEncryptionProvider");
}
```

                
