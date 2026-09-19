import { api } from './api';
import { TokenResponse, User } from '../types/auth';
import { HealthResponse } from '../types/health';

export const authService = {
  async login(username: string, password: string): Promise<TokenResponse> {
    const response = await api.post<TokenResponse>('/auth/login', { username, password });
    return response.data;
  },

  async register(
    username: string,
    fullName: string,
    password: string,
    requestedRole: string = 'Viewer'
  ): Promise<User> {
    const response = await api.post<User>('/auth/register', {
      username,
      full_name: fullName,
      password,
      requested_role: requestedRole,
    });
    return response.data;
  },

  async getCurrentUser(): Promise<User> {
    const response = await api.get<User>('/auth/me');
    return response.data;
  },

  async getHealth(): Promise<HealthResponse> {
    const response = await api.get<HealthResponse>('/health');
    return response.data;
  },

  async testAdminAction(): Promise<{ status: string; message: string }> {
    const response = await api.get<{ status: string; message: string }>('/auth/admin-only-action');
    return response.data;
  },
};
