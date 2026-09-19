export type UserRoleName = 
  | 'Viewer' 
  | 'Incident Responder' 
  | 'Security Analyst' 
  | 'Security Admin';

export interface Role {
  id: string;
  name: UserRoleName;
  description?: string;
}

export interface User {
  id: string;
  username: string;
  full_name: string;
  is_active: boolean;
  roles: Role[];
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}
