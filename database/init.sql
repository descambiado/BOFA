-- BOFA Extended Systems v2.5.0 - Database Initialization
-- PostgreSQL Database Schema

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    login_count INTEGER DEFAULT 0
);

-- Script execution history
CREATE TABLE IF NOT EXISTS script_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    script_name VARCHAR(100) NOT NULL,
    module VARCHAR(50) NOT NULL,
    parameters JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL CHECK (status IN ('running', 'success', 'error', 'warning')),
    output TEXT,
    error_message TEXT,
    execution_time INTEGER, -- in milliseconds
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Lab instances for tracking active labs
CREATE TABLE IF NOT EXISTS lab_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    lab_name VARCHAR(100) NOT NULL,
    container_id VARCHAR(100),
    status VARCHAR(20) NOT NULL CHECK (status IN ('starting', 'running', 'stopped', 'error')),
    port_mappings JSONB DEFAULT '{}',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    stopped_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- System metrics for dashboard
CREATE TABLE IF NOT EXISTS system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(50) NOT NULL,
    metric_value DECIMAL,
    metric_data JSONB DEFAULT '{}',
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Threat detection events
CREATE TABLE IF NOT EXISTS threat_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    title VARCHAR(200) NOT NULL,
    description TEXT,
    source_ip INET,
    target_ip INET,
    mitre_tactic VARCHAR(50),
    mitre_technique VARCHAR(50),
    ioc_data JSONB DEFAULT '{}',
    raw_data JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API keys and tokens
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    service_name VARCHAR(50) NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Learning progress tracking
CREATE TABLE IF NOT EXISTS learning_progress (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    course_name VARCHAR(100) NOT NULL,
    lesson_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'not_started' CHECK (status IN ('not_started', 'in_progress', 'completed')),
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, course_name, lesson_name)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_script_executions_user_id ON script_executions(user_id);
CREATE INDEX IF NOT EXISTS idx_script_executions_status ON script_executions(status);
CREATE INDEX IF NOT EXISTS idx_script_executions_created_at ON script_executions(created_at);
CREATE INDEX IF NOT EXISTS idx_script_executions_module ON script_executions(module);

CREATE INDEX IF NOT EXISTS idx_lab_instances_user_id ON lab_instances(user_id);
CREATE INDEX IF NOT EXISTS idx_lab_instances_status ON lab_instances(status);

CREATE INDEX IF NOT EXISTS idx_threat_events_severity ON threat_events(severity);
CREATE INDEX IF NOT EXISTS idx_threat_events_status ON threat_events(status);
CREATE INDEX IF NOT EXISTS idx_threat_events_created_at ON threat_events(created_at);

CREATE INDEX IF NOT EXISTS idx_system_metrics_metric_name ON system_metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_system_metrics_recorded_at ON system_metrics(recorded_at);

CREATE INDEX IF NOT EXISTS idx_learning_progress_user_id ON learning_progress(user_id);
CREATE INDEX IF NOT EXISTS idx_learning_progress_status ON learning_progress(status);

-- Insert default admin user (password: admin123)
INSERT INTO users (username, email, password_hash, full_name, is_admin) 
VALUES (
    'admin',
    'admin@bofa.local',
    '$2b$12$LQv3c1yQBE8FRP0pnQtJUeehufZyV.7jNAKJ/gLT3D5Y5O8mZHsW.',
    'BOFA Administrator',
    TRUE
) ON CONFLICT (username) DO NOTHING;

-- Insert sample system metrics
INSERT INTO system_metrics (metric_name, metric_value, metric_data) VALUES
    ('scripts_executed_total', 0, '{"module_breakdown": {}}'),
    ('threats_detected_total', 0, '{"severity_breakdown": {}}'),
    ('labs_active', 0, '{"lab_breakdown": {}}'),
    ('security_score', 85, '{"components": {"network": 90, "host": 80, "application": 85}}')
ON CONFLICT DO NOTHING;

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_events_updated_at BEFORE UPDATE ON threat_events
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_learning_progress_updated_at BEFORE UPDATE ON learning_progress
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();