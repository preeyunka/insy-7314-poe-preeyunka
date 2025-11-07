# DevSecOps Security Implementation

## 1. Dependency Security Using npm audit

To ensure a secure backend, I implemented automated vulnerability scanning using npm audit  
This tool checks all dependencies in the `package.json` file against the Node Security Platform (NSP) database to identify known vulnerabilities

### Commands Used:
```bash
npm audit
npm audit fix
npm audit fix --force
