import csv
import json
import time
import requests

# CONFIGURAÇÃO: Insira suas chaves de API aqui
ABUSEIPDB_API_KEY = "1a80707f7aa785545f10b3cd06d8f4ddfbccab9d0c7332fbac91dda97df9da6bd7497d486a815ce7"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
OTX_API_KEY = "YOUR_ALIENVAULT_OTX_API_KEY"

# Lista de IPs a serem analisados (mude o tipo do arquivo se precisar)
INPUT_FILE = "ips.txt"

# Carrega a lista de IPs do arquivo
def check_abuseipdb(ip: str) -> dict:
    """Consulta pontuação de abuso e país no AbuseIPDB."""
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY.startswith("SUA_CHAVE"):
        return {"score": 0, "country": "N/A"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Desconhecido")
            }
    except Exception as e:
        print(f"[!] Erro AbuseIPDB ({ip}): {e}")
    return {"score": 0, "country": "Desconhecido"}

# Consulta detecções de segurança no VirusTotal
def check_virustotal(ip: str) -> dict:
    """Consulta detecções de segurança no VirusTotal."""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY.startswith("SUA_CHAVE"):
        return {"malicious": 0, "total": 0, "country": "N/A"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            attr = response.json().get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            return {
                "malicious": malicious + suspicious,
                "total": total,
                "country": attr.get("country", "Desconhecido")
            }
    except Exception as e:
        print(f"[!] Erro VirusTotal ({ip}): {e}")
    return {"malicious": 0, "total": 0, "country": "Desconhecido"}

# Consulta contagem de pulso de ameaça no AlienVault OTX
def check_alienvault_otx(ip: str) -> int:
    """Consulta contagem de pulso de ameaça no AlienVault OTX (Sem chave obrigatória)."""
    headers = {}
    if OTX_API_KEY and not OTX_API_KEY.startswith("SUA_CHAVE"):
        headers["X-OTX-API-KEY"] = OTX_API_KEY

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            pulse_info = response.json().get("pulse_info", {})
            return pulse_info.get("count", 0)
    except Exception as e:
        print(f"[!] Erro AlienVault OTX ({ip}): {e}")
    return 0

# Função principal para analisar a lista de IPs
def analyze_ips(ip_list: list) -> list:
    results = []

    print("[*] Iniciando análise de Threat Intelligence...\n")

    for ip in ip_list:
        print(f"-> Consultando {ip}...")

        abuse_data = check_abuseipdb(ip)
        vt_data = check_virustotal(ip)
        otx_pulses = check_alienvault_otx(ip)

        # Determina o país priorizando a API que retornar a informação
        country = abuse_data["country"] if abuse_data["country"] != "Desconhecido" else vt_data["country"]

        # Normalização do Nível de Risco (0 a 100)
        vt_score = (vt_data["malicious"] / vt_data["total"] * 100) if vt_data["total"] > 0 else 0
        abuse_score = abuse_data["score"]
        otx_score = min(otx_pulses * 10, 100)  # Cada pulso vale 10% de risco, limitado a 100%

        # Média ponderada: AbuseIPDB (40%), VirusTotal (40%), OTX (20%)
        overall_risk = round((abuse_score * 0.4) + (vt_score * 0.4) + (otx_score * 0.2), 2)

        results.append({
            "ip": ip,
            "overall_risk_score": overall_risk,
            "country": country,
            "details": {
                "abuseipdb_confidence_score": abuse_score,
                "virustotal_detections": f"{vt_data['malicious']}/{vt_data['total']}",
                "alienvault_pulses": otx_pulses
            }
        })

        # Respeita limites do plano gratuito da API do VirusTotal (4 requisições/minuto)
        time.sleep(15)

    # Ordena os IPs do maior para o menor nível de risco
    results.sort(key=lambda x: x["overall_risk_score"], reverse=True)
    return results

# Funções para exportar os resultados em JSON e CSV
def export_json(data: list, filename="threat_intel_report.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"\n[+] Relatório JSON gerado: {filename}")


def export_csv(data: list, filename="threat_intel_report.csv"):
    keys = ["ip", "overall_risk_score", "country", "abuseipdb_confidence_score", "virustotal_detections", "alienvault_pulses"]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(keys)
        for row in data:
            writer.writerow([
                row["ip"],
                row["overall_risk_score"],
                row["country"],
                row["details"]["abuseipdb_confidence_score"],
                row["details"]["virustotal_detections"],
                row["details"]["alienvault_pulses"]
            ])
    print(f"[+] Relatório CSV gerado: {filename}")

# Carrega a lista de IPs do arquivo
if __name__ == "__main__":
    report_data = analyze_ips([line.strip() for line in open(INPUT_FILE) if line.strip()])
    export_json(report_data)
    export_csv(report_data)