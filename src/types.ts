export interface EnclistFile {
  object: string;
}

export interface Enclist {
  version: 1;
  vaultId: string;
  authServer: string;
  files: Record<string, EnclistFile>;
}

export interface WrappedKey {
  kid: string;
  nonce: string;
  ciphertext: string;
  tag: string;
}

export interface EncryptedFile {
  version: 1;
  cipher: "aes-256-gcm";
  nonce: string;
  ciphertext: string;
  tag: string;
  wrappedKey: WrappedKey;
}

export interface TeamRule {
  organization: string;
  slug: string;
}

export interface AccessRule {
  users: number[];
  teams: TeamRule[];
}

export interface ServerVault {
  repository: string;
  files: Record<string, AccessRule>;
}

export interface DevelopmentUser {
  id: number;
  login: string;
}

export interface ServerPolicy {
  version: 1;
  githubClientId?: string;
  sessionMinutes: number;
  keyId: string;
  developmentUsers: DevelopmentUser[];
  vaults: Record<string, ServerVault>;
}

export interface LocalSession {
  server: string;
  token: string;
  expiresAt: string;
  user: {
    id: number;
    login: string;
  };
}

export interface MaterializedFile {
  path: string;
  digest: string;
}

export interface RepositoryInstance {
  device: string;
  inode: string;
}

export interface MaterializationLease {
  version: 1;
  repositoryId: string;
  repositoryInstance: RepositoryInstance;
  generation: string;
  root: string;
  server: string;
  expiresAt: string;
  userId: number;
  sessionId: string;
  paths: MaterializedFile[];
}
