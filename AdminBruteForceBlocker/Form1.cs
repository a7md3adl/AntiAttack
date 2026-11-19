using System;
using System.Diagnostics;
using System.Drawing;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AdminBruteForceBlocker
{
    public partial class MainForm : Form
    {
        private Button btnScanBlock;
        private Button btn24ScanBlock;
        private RichTextBox txtOutput;
        private Label lblStatus;

        public MainForm()
        {
            InitializeComponent();
            SetupCustomLayout();
        }

        private void SetupCustomLayout()
        {
            Panel mainPanel = new Panel();
            mainPanel.Padding = new Padding(10);
            mainPanel.Height = 50;
            mainPanel.Dock = DockStyle.Top;
            this.Controls.Add(mainPanel);
            this.Text = "Administrator Brute-Force IP Blocker By [Ahmed Adel]";
            this.Size = new Size(900, 700);
            this.StartPosition = FormStartPosition.CenterScreen;

            // Status Label
            lblStatus = new Label();
            lblStatus.Text = "Status: Ready to scan Security Event Log.";
            lblStatus.Location = new Point(12, 15);
            lblStatus.AutoSize = true;
            lblStatus.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            lblStatus.Dock = DockStyle.Left;
            mainPanel.Controls.Add(lblStatus);

            // Action Button
            btn24ScanBlock = new Button();
            btn24ScanBlock.Text = "Grouping Attacker IPs into /24";
            btn24ScanBlock.Location = new Point(480, 12);
            btn24ScanBlock.Size = new Size(190, 30);
            btn24ScanBlock.UseVisualStyleBackColor = true;
            btn24ScanBlock.Click += btn24ScanBlock_Click;
            btn24ScanBlock.Dock = DockStyle.Right;
            mainPanel.Controls.Add(btn24ScanBlock);
            
            
            
            btnScanBlock = new Button();
            btnScanBlock.Text = "Scan & Block Attacker IPs";
            btnScanBlock.Location = new Point(480, 12);
            btnScanBlock.Size = new Size(190, 30);
            btnScanBlock.UseVisualStyleBackColor = true;
            btnScanBlock.Click += BtnScanBlock_Click;
            btnScanBlock.Dock = DockStyle.Right;
            mainPanel.Controls.Add(btnScanBlock);

            // Output TextBox
            txtOutput = new RichTextBox();
            txtOutput.Location = new Point(12, 55);
            txtOutput.Size = new Size(660, 390);
            txtOutput.Font = new Font("Consolas", 9.5f);
            txtOutput.BackColor = Color.FromArgb(30, 30, 30);
            txtOutput.ForeColor = Color.LightGreen;
            txtOutput.ReadOnly = true;
            txtOutput.Dock = DockStyle.Fill;
            txtOutput.BorderStyle = BorderStyle.None;

            Panel BodyPanel = new Panel();
            BodyPanel.Padding = new Padding(10);
            BodyPanel.Dock = DockStyle.Fill;
            BodyPanel.BackColor = Color.FromArgb(30, 30, 30);
            this.Controls.Add(BodyPanel);
            BodyPanel.Controls.Add(txtOutput);
            mainPanel.SendToBack();
            BodyPanel.BringToFront();

            txtOutput.Margin = new Padding(10);
        }

        private async void btn24ScanBlock_Click(object sender, EventArgs e)
        {
            btn24ScanBlock.Enabled = false;
            txtOutput.Clear();
            lblStatus.Text = "Status: Scanning Security Logs & Grouping Attacker IPs into /24 Subnets...";
            lblStatus.ForeColor = Color.DarkOrange;

            string psScript = @"
    Write-Host '=== Scanning Security Logs & Grouping Attacker IPs into /24 Subnets ==='

    # 1. Fetch failed logon events (adjust -MaxEvents as needed)
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 1000 -ErrorAction SilentlyContinue

    $ipv4List = foreach ($evt in $events) {
        try {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($item in $xml.Event.EventData.Data) {
                $data[$item.Name] = $item.'#text'
            }

            $ip = $data['IpAddress']
            if ($data['TargetUserName'] -eq 'Administrator' -and
                $ip -and
                $ip -ne '-' -and
                $ip -ne '127.0.0.1' -and
                $ip -ne '::1' -and
                $ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
                $ip
            }
        } catch {}
    }

    $uniqueIPs = @($ipv4List | Select-Object -Unique)

    if ($uniqueIPs.Count -eq 0) {
        Write-Host 'No external IPv4 attacker addresses found for Administrator.'
        return
    }

    # 2. Convert each IPv4 address to its /24 network prefix (e.g., 194.165.16.167 -> 194.165.16.0/24)
    $subnetGroups = $uniqueIPs | ForEach-Object {
        $octets = $_.Split('.')
        [PSCustomObject]@{
            IP     = $_
            Subnet = ($octets[0] + '.' + $octets[1] + '.' + $octets[2] + '.0/24')
        }
    } | Group-Object -Property Subnet | Sort-Object -Property Count -Descending

    $summaryMsg = 'Found ' + $uniqueIPs.Count + ' unique IP(s) across ' + $subnetGroups.Count + ' /24 subnet(s):'
    Write-Host $summaryMsg
    Write-Host ''

    foreach ($grp in $subnetGroups) {
        $ipsInSubnet = ($grp.Group | Select-Object -ExpandProperty IP) -join ', '
        $line = '  -> ' + $grp.Name + ' (' + $grp.Count + ' IP(s)): ' + $ipsInSubnet
        Write-Host $line
    }

    # 3. Block each /24 subnet cleanly in Windows Firewall
    Write-Host ''
    Write-Host '[+] Applying Windows Firewall /24 Inbound Block Rules...'

    foreach ($grp in $subnetGroups) {
        $subnet = $grp.Name
        $ruleName = 'Block BruteForce Subnet - ' + $subnet

        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -RemoteAddress $subnet -Action Block | Out-Null
            Write-Host (' [BLOCKED] ' + $subnet)
        } else {
            Write-Host (' [SKIPPED] Rule already exists for ' + $subnet)
        }
    }

    Write-Host ''
    Write-Host '=== /24 Subnet Mitigation Complete ==='
";

            await Task.Run(() => RunPowerShellScript(psScript));

            btn24ScanBlock.Enabled = true;
            lblStatus.Text = "Status: Scan and block operation completed.";
            lblStatus.ForeColor = Color.Green;
        }

        private async void BtnScanBlock_Click(object sender, EventArgs e)
        {
            btnScanBlock.Enabled = false;
            txtOutput.Clear();
            lblStatus.Text = "Status: Running PowerShell Scan & Firewall Block...";
            lblStatus.ForeColor = Color.DarkOrange;

            // Embedded PowerShell script that performs the event parsing and firewall rule creation
            string psScript = @"
                $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 500 -ErrorAction SilentlyContinue
                $badIPs = foreach ($evt in $events) {
                    try {
                        $xml = [xml]$evt.ToXml()
                        $data = @{}
                        foreach ($item in $xml.Event.EventData.Data) {
                            $data[$item.Name] = $item.'#text'
                        }
                        if ($data['TargetUserName'] -eq 'Administrator' -and 
                            $data['IpAddress'] -and 
                            $data['IpAddress'] -ne '-' -and 
                            $data['IpAddress'] -ne '127.0.0.1' -and 
                            $data['IpAddress'] -ne '::1') {
                            $data['IpAddress']
                        }
                    } catch {}
                }
                $uniqueIPs = $badIPs | Select-Object -Unique
                if (-not $uniqueIPs) {
                    Write-Host 'No external source IPs found targeting Administrator.'
                    return
                }

                $countMsg = 'Found ' + $uniqueIPs.Count + ' unique external source IP(s) attacking Administrator:'
                Write-Host $countMsg

                foreach ($ip in $uniqueIPs) {
                    Write-Host ('  -> IP: ' + $ip)
                }

                Write-Host 'Applying Windows Firewall Inbound Block Rules...'
                
                foreach ($ip in $uniqueIPs) {
                    $ruleName = 'Block BruteForce IP - ' + $ip
                    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -RemoteAddress $ip -Action Block | Out-Null
                        Write-Host ('[BLOCKED] Successfully blocked IP: ' + $ip)
                    } else {
                        Write-Host ('[SKIPPED] Rule already exists for IP: ' + $ip)
                    }
                }
                Write-Host 'Mitigation Complete.'
            ";

            await Task.Run(() => RunPowerShellScript(psScript));

            btnScanBlock.Enabled = true;
            lblStatus.Text = "Status: Scan and block operation completed.";
            lblStatus.ForeColor = Color.Green;
        }

        private void RunPowerShellScript(string scriptContent)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{scriptContent}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(psi))
                {
                    // Read output line by line and append to UI thread safely
                    while (!process.StandardOutput.EndOfStream)
                    {
                        string line = process.StandardOutput.ReadLine();
                        AppendOutputText(line + Environment.NewLine);
                    }

                    string errors = process.StandardError.ReadToEnd();
                    if (!string.IsNullOrEmpty(errors))
                    {
                        AppendOutputText("ERRORS: " + errors + Environment.NewLine);
                    }

                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                AppendOutputText("Execution Exception: " + ex.Message + Environment.NewLine);
            }
        }

        private void AppendOutputText(string text)
        {
            if (txtOutput.InvokeRequired)
            {
                txtOutput.Invoke(new Action<string>(AppendOutputText), text);
            }
            else
            {
                txtOutput.AppendText(text);
                txtOutput.ScrollToCaret();
            }
        }
    }
}