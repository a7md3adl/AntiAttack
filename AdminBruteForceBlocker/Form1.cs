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
        private RichTextBox txtOutput;
        private Label lblStatus;

        public MainForm()
        {
            InitializeComponent();
            SetupCustomLayout();
        }

        private void SetupCustomLayout()
        {
            this.Text = "Administrator Brute-Force IP Blocker By [Ahmed Adel]";
            this.Size = new Size(700, 500);
            this.StartPosition = FormStartPosition.CenterScreen;

            // Status Label
            lblStatus = new Label();
            lblStatus.Text = "Status: Ready to scan Security Event Log.";
            lblStatus.Location = new Point(12, 15);
            lblStatus.AutoSize = true;
            lblStatus.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            this.Controls.Add(lblStatus);

            // Action Button
            btnScanBlock = new Button();
            btnScanBlock.Text = "Scan & Block Attacker IPs";
            btnScanBlock.Location = new Point(480, 12);
            btnScanBlock.Size = new Size(190, 30);
            btnScanBlock.UseVisualStyleBackColor = true;
            btnScanBlock.Click += BtnScanBlock_Click;
            this.Controls.Add(btnScanBlock);

            // Output TextBox
            txtOutput = new RichTextBox();
            txtOutput.Location = new Point(12, 55);
            txtOutput.Size = new Size(660, 390);
            txtOutput.Font = new Font("Consolas", 9.5f);
            txtOutput.BackColor = Color.FromArgb(30, 30, 30);
            txtOutput.ForeColor = Color.LightGreen;
            txtOutput.ReadOnly = true;
            this.Controls.Add(txtOutput);
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
                Write-Host 'Found $($uniqueIPs.Count) unique external source IP(s) attacking Administrator:'
                $uniqueIPs | ForEach-Object { Write-Host '  -> IP: $_' }
                Write-Host '`nApplying Windows Firewall Inbound Block Rules...'
                foreach ($ip in $uniqueIPs) {
                    $ruleName = 'Block BruteForce IP - ' + $ip
                    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -RemoteAddress $ip -Action Block | Out-Null
                        Write-Host '[BLOCKED] Successfully blocked IP: $ip' -ForegroundColor Red
                    } else {
                        Write-Host '[SKIPPED] Rule already exists for IP: $ip' -ForegroundColor DarkGray
                    }
                }
                Write-Host '`nMitigation Complete.'
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