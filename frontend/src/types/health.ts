export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'offline';
  version: string;
  timestamp: string;
  database: string;
  details?: {
    service?: string;
    api_version?: string;
    database_error?: string | null;
    security_mode?: string;
  };
}
