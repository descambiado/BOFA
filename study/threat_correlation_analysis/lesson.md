# Threat Correlation Analysis - Blue Team Advanced Analytics

## 🎯 Objetivo de la Lección
Dominar técnicas avanzadas de correlación de amenazas para detectar ataques complejos mediante análisis de patrones y eventos de seguridad en tiempo real.

## 📚 Fundamentos de Correlación de Amenazas

### ¿Qué es Threat Correlation?
La correlación de amenazas es el proceso de identificar relaciones entre eventos de seguridad aparentemente independientes para detectar ataques coordinados y campañas persistentes.

### Componentes Clave
1. **Event Ingestion** - Recolección de eventos de múltiples fuentes
2. **Pattern Recognition** - Identificación de patrones maliciosos
3. **Timeline Analysis** - Análisis temporal de actividades
4. **Risk Scoring** - Evaluación de severidad y confianza
5. **Alert Generation** - Generación de alertas contextualizadas

## 🔍 Técnicas de Correlación

### 1. Correlación Temporal
```python
# Ventana de tiempo para correlación
correlation_window = timedelta(minutes=30)

# Eventos relacionados temporalmente
def correlate_by_time(events, window):
    correlated_groups = []
    for event in events:
        related_events = [
            e for e in events 
            if abs((e.timestamp - event.timestamp).total_seconds()) <= window.total_seconds()
        ]
        if len(related_events) >= threshold:
            correlated_groups.append(related_events)
    return correlated_groups
```

### 2. Correlación por IP/Host
```python
# Agrupar eventos por origen
def correlate_by_source(events):
    source_groups = {}
    for event in events:
        key = f"{event.source_ip}:{event.target_ip}"
        if key not in source_groups:
            source_groups[key] = []
        source_groups[key].append(event)
    return source_groups
```

### 3. Correlación por Técnica MITRE
```python
# Mapeo de técnicas MITRE ATT&CK
mitre_chains = {
    'credential_access': ['T1110', 'T1078', 'T1003'],
    'lateral_movement': ['T1021', 'T1055', 'T1135'],
    'exfiltration': ['T1041', 'T1048', 'T1567']
}

def correlate_by_mitre(events):
    for chain_name, techniques in mitre_chains.items():
        matching_events = [
            e for e in events 
            if e.mitre_technique in techniques
        ]
        if len(matching_events) >= 2:
            yield chain_name, matching_events
```

## 🎲 Patrones de Ataque Comunes

### 1. Credential Stuffing Attack
```
Timeline Pattern:
[09:15:23] failed_login (user1@192.168.1.100)
[09:15:24] failed_login (user2@192.168.1.100) 
[09:15:25] failed_login (admin@192.168.1.100)
[09:15:45] successful_login (admin@192.168.1.100)
[09:16:02] privilege_escalation (admin@192.168.1.100)

Correlation Rule:
- Events: failed_login (>10) + successful_login
- Time Window: 5 minutes
- Same Source IP
- MITRE: T1110 + T1078
```

### 2. Lateral Movement Campaign
```
Timeline Pattern:
[10:30:15] network_connection (WS-001 -> SRV-001:445)
[10:30:32] process_creation (SRV-001: powershell.exe)
[10:31:05] file_access (SRV-001: \\SRV-002\C$\)
[10:31:20] network_connection (SRV-001 -> SRV-002:3389)
[10:32:15] user_login (SRV-002: corp\compromised_user)

Correlation Rule:
- Events: network_connection + process_creation + file_access
- Progressive host compromise
- MITRE: T1021 + T1055 + T1083
```

### 3. Data Exfiltration Operation
```
Timeline Pattern:
[14:20:10] file_access (sensitive_documents/*.xlsx)
[14:22:30] file_compression (archive.zip creation)
[14:25:45] network_transfer (50MB -> external_ip)
[14:26:10] dns_query (suspicious_domain.com)
[14:27:00] https_transfer (completed)

Correlation Rule:
- Events: file_access + network_transfer (large volume)
- Sequence: Access -> Compress -> Transfer
- MITRE: T1083 + T1041 + T1048
```

## 🛠️ Herramientas de Correlación

### 1. Real-Time Threat Correlator
```bash
# Iniciar correlator en tiempo real
python3 real_time_threat_correlator.py --real-time --events 100

# Simular ataque de fuerza bruta
python3 real_time_threat_correlator.py --simulate brute_force --duration 60

# Simular movimiento lateral
python3 real_time_threat_correlator.py --simulate lateral_movement --duration 120

# Análisis de logs existentes
python3 real_time_threat_correlator.py --analyze-logs security.log --output analysis.json
```

### 2. SIEM Alert Simulator
```bash
# Generar alertas de entrenamiento
python3 siem_alert_simulator.py -c 50 -f 10 -o training_alerts.json

# Tipos específicos de alertas
python3 siem_alert_simulator.py -t brute_force malware_detection -c 25

# Simulación en tiempo real
python3 siem_alert_simulator.py --real-time --help-mitre
```

## 📊 Métricas y Scoring

### 1. Confidence Scoring
```python
def calculate_confidence(events, rule):
    base_confidence = 0.5
    
    # Factor de frecuencia
    frequency_factor = min(1.0, len(events) / rule['min_events'])
    
    # Factor temporal
    time_span = max(e.timestamp for e in events) - min(e.timestamp for e in events)
    time_factor = max(0.1, 1.0 - (time_span.total_seconds() / rule['time_window'].total_seconds()))
    
    # Factor de diversidad de fuentes
    unique_sources = len(set(e.source_ip for e in events))
    source_factor = 0.8 if unique_sources == 1 else 0.6
    
    confidence = base_confidence * frequency_factor * time_factor * source_factor
    return min(1.0, confidence)
```

### 2. Risk Level Classification
```python
def classify_risk(confidence, event_severity):
    weighted_score = (confidence * 0.6) + (event_severity / 10 * 0.4)
    
    if weighted_score >= 0.8:
        return "CRITICAL"
    elif weighted_score >= 0.6:
        return "HIGH"  
    elif weighted_score >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"
```

## 🔬 Análisis Avanzado

### 1. Behavioral Analytics
```python
# Análisis de comportamiento normal vs anómalo
def analyze_user_behavior(user_events, baseline_behavior):
    anomalies = []
    
    # Horarios inusuales
    normal_hours = baseline_behavior.get('typical_hours', (8, 18))
    for event in user_events:
        hour = event.timestamp.hour
        if hour < normal_hours[0] or hour > normal_hours[1]:
            anomalies.append({
                'type': 'unusual_time',
                'event': event,
                'severity': 6
            })
    
    # Ubicaciones inusuales  
    normal_ips = baseline_behavior.get('typical_ips', [])
    for event in user_events:
        if event.source_ip not in normal_ips:
            anomalies.append({
                'type': 'unusual_location',
                'event': event,
                'severity': 7
            })
    
    return anomalies
```

### 2. Attack Chain Reconstruction
```python
def reconstruct_attack_chain(correlated_events):
    # Ordenar eventos cronológicamente
    sorted_events = sorted(correlated_events, key=lambda x: x.timestamp)
    
    attack_phases = {
        'reconnaissance': [],
        'initial_access': [],
        'execution': [],
        'persistence': [],
        'privilege_escalation': [],
        'defense_evasion': [],
        'credential_access': [],
        'discovery': [],
        'lateral_movement': [],
        'collection': [],
        'exfiltration': []
    }
    
    # Mapear eventos a fases de ataque
    for event in sorted_events:
        phase = map_mitre_to_phase(event.mitre_technique)
        attack_phases[phase].append(event)
    
    return attack_phases
```

## 🧪 Ejercicios Prácticos

### Ejercicio 1: Detección de Brute Force
```bash
# 1. Iniciar correlator
python3 real_time_threat_correlator.py --real-time &

# 2. Simular ataque
python3 siem_alert_simulator.py -t brute_force -c 20 --real-time

# 3. Analizar patrones detectados
# Observar correlaciones en tiempo real
```

### Ejercicio 2: Análisis de Movimiento Lateral
```bash
# Simular campaña completa
python3 real_time_threat_correlator.py --simulate lateral_movement --duration 180

# Exportar resultados
python3 real_time_threat_correlator.py --output lateral_analysis.json

# Analizar cadena de ataque
cat lateral_analysis.json | jq '.patterns[].attack_timeline'
```

### Ejercicio 3: Correlación Multi-Vector
```bash
# Generar eventos mixtos
python3 siem_alert_simulator.py -t brute_force lateral_movement data_exfiltration -c 100

# Correlacionar patrones complejos
python3 real_time_threat_correlator.py --real-time --complex-rules
```

## 📈 Optimización de Correlación

### 1. Tuning de Reglas
```yaml
# correlation_rules.yaml
credential_stuffing:
  min_events: 15        # Reducir falsos positivos
  time_window: 300      # 5 minutos
  confidence_threshold: 0.7
  severity_weight: 0.8

lateral_movement:
  min_events: 5
  time_window: 900      # 15 minutos  
  host_diversity: true  # Múltiples hosts
  protocol_variety: 2   # Mínimo 2 protocolos
```

### 2. Performance Optimization
```python
# Indexación por tiempo
def optimize_event_search(events):
    time_index = {}
    for event in events:
        time_bucket = event.timestamp.replace(second=0, microsecond=0)
        if time_bucket not in time_index:
            time_index[time_bucket] = []
        time_index[time_bucket].append(event)
    return time_index

# Filtrado eficiente
def efficient_correlation(events, rules):
    for rule_name, rule_config in rules.items():
        # Pre-filtrar por tipo de evento
        relevant_events = [
            e for e in events 
            if e.event_type in rule_config['events']
        ]
        
        # Aplicar correlación solo a eventos relevantes
        yield from correlate_events(relevant_events, rule_config)
```

## 🎯 Casos de Estudio

### Caso 1: APT Campaign Detection
```
Scenario: Advanced Persistent Threat
- Duración: 30 días
- Técnicas: Spear phishing -> Lateral movement -> Data exfiltration
- Indicadores: Subtle anomalies, low-and-slow approach
- Desafío: Detectar patrones distribuidos en tiempo
```

### Caso 2: Insider Threat Analysis
```
Scenario: Empleado malicioso
- Comportamiento: Acceso fuera de horario, descarga masiva
- Correlación: User behavior + data access + network activity
- Indicadores: Anomalías de comportamiento, violation de políticas
```

### Caso 3: Supply Chain Attack
```
Scenario: Compromiso de software legítimo
- Vector: Update mechanism compromise
- Correlación: Software updates + network callbacks + persistence
- Desafío: Distinguir actividad legítima vs maliciosa
```

## ✅ Validación de Competencias

### Conocimientos Teóricos
- [ ] Comprendes tipos de correlación (temporal, espacial, behavioral)
- [ ] Dominas métricas de confidence y risk scoring
- [ ] Entiendes mapeo MITRE ATT&CK para correlación
- [ ] Sabes reconstruir attack chains completas
- [ ] Comprendes optimización de reglas de correlación

### Habilidades Prácticas  
- [ ] Configuras correlators en tiempo real
- [ ] Desarrollas reglas de correlación custom
- [ ] Analizas falsos positivos y ajustas umbrales
- [ ] Generas reportes de threat intelligence
- [ ] Optimizas performance de correlación

## 🚀 Aplicaciones Avanzadas

### 1. Machine Learning Integration
```python
# Correlación asistida por ML
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

def ml_assisted_correlation(events):
    # Feature extraction
    features = extract_features(events)
    
    # Clustering de eventos similares
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)
    
    clustering = DBSCAN(eps=0.5, min_samples=3)
    clusters = clustering.fit_predict(scaled_features)
    
    return group_events_by_cluster(events, clusters)
```

### 2. Threat Intelligence Integration
```python
# Enriquecimiento con TI
def enrich_with_threat_intel(events, ti_feeds):
    enriched_events = []
    
    for event in events:
        enrichment = {}
        
        # Verificar IOCs conocidos
        if event.source_ip in ti_feeds['malicious_ips']:
            enrichment['ti_classification'] = 'known_malicious'
            enrichment['confidence'] += 0.3
        
        # Verificar dominios sospechosos
        if any(domain in event.raw_data.get('dns_query', '') 
               for domain in ti_feeds['suspicious_domains']):
            enrichment['ti_classification'] = 'suspicious_domain'
            enrichment['confidence'] += 0.2
        
        event.enrichment = enrichment
        enriched_events.append(event)
    
    return enriched_events
```

## 📚 Recursos Adicionales

### Documentación
- NIST SP 800-61: Computer Security Incident Handling Guide
- SANS SEC504: Hacker Tools, Techniques, Exploits and Incident Handling
- MITRE ATT&CK Framework Documentation

### Herramientas Relacionadas
- `real_time_threat_correlator.py` - Correlador principal
- `siem_alert_simulator.py` - Generador de alertas
- `ai_threat_hunter.py` - Hunter asistido por IA

### Fuentes de Threat Intelligence
- MISP (Malware Information Sharing Platform)
- OpenIOC Framework
- STIX/TAXII Standards
- Commercial TI Feeds

---

**⚠️ Nota Importante**: Esta lección está diseñada para profesionales de blue team y analistas de seguridad. Aplica estos conocimientos únicamente en entornos autorizados y como parte de estrategias defensivas legítimas.