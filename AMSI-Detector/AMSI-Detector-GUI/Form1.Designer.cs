namespace AMSI_Detector_GUI
{
    partial class AMSIDetector
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AMSIDetector));
            this.choosePnl = new System.Windows.Forms.Panel();
            this.textBox3 = new System.Windows.Forms.TextBox();
            this.scanBtn = new System.Windows.Forms.Button();
            this.startupBtn = new System.Windows.Forms.Button();
            this.infoTxt = new System.Windows.Forms.TextBox();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.textBox2 = new System.Windows.Forms.TextBox();
            this.panel1 = new System.Windows.Forms.Panel();
            this.textBox4 = new System.Windows.Forms.TextBox();
            this.panel2 = new System.Windows.Forms.Panel();
            this.scanTooltip = new System.Windows.Forms.ToolTip(this.components);
            this.startupTooltip = new System.Windows.Forms.ToolTip(this.components);
            this.choosePnl.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.panel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // choosePnl
            // 
            this.choosePnl.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(0)))), ((int)(((byte)(64)))));
            this.choosePnl.Controls.Add(this.textBox3);
            this.choosePnl.Controls.Add(this.scanBtn);
            this.choosePnl.Location = new System.Drawing.Point(482, -1);
            this.choosePnl.Name = "choosePnl";
            this.choosePnl.Size = new System.Drawing.Size(385, 240);
            this.choosePnl.TabIndex = 0;
            // 
            // textBox3
            // 
            this.textBox3.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(0)))), ((int)(((byte)(64)))));
            this.textBox3.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox3.Cursor = System.Windows.Forms.Cursors.Arrow;
            this.textBox3.Font = new System.Drawing.Font("Cascadia Code", 10.8F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(163)));
            this.textBox3.ForeColor = System.Drawing.Color.White;
            this.textBox3.Location = new System.Drawing.Point(21, 115);
            this.textBox3.Multiline = true;
            this.textBox3.Name = "textBox3";
            this.textBox3.ReadOnly = true;
            this.textBox3.Size = new System.Drawing.Size(348, 107);
            this.textBox3.TabIndex = 6;
            this.textBox3.Text = "- Manual Scan for AMSI Bypass\r\n- Detects known AMSI bypass techniques in running " +
    "PowerShell processes.";
            // 
            // scanBtn
            // 
            this.scanBtn.BackColor = System.Drawing.Color.ForestGreen;
            this.scanBtn.FlatAppearance.BorderSize = 0;
            this.scanBtn.Font = new System.Drawing.Font("Poppins Black", 10.8F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.scanBtn.ForeColor = System.Drawing.Color.White;
            this.scanBtn.Location = new System.Drawing.Point(69, 29);
            this.scanBtn.Name = "scanBtn";
            this.scanBtn.Size = new System.Drawing.Size(250, 70);
            this.scanBtn.TabIndex = 0;
            this.scanBtn.Text = "SCAN AMSI";
            this.scanTooltip.SetToolTip(this.scanBtn, "Click to perform a one-time scan for AMSI tampering.");
            this.scanBtn.UseVisualStyleBackColor = false;
            this.scanBtn.Click += new System.EventHandler(this.scanBtn_Click);
            // 
            // startupBtn
            // 
            this.startupBtn.BackColor = System.Drawing.Color.Chocolate;
            this.startupBtn.FlatAppearance.BorderSize = 0;
            this.startupBtn.Font = new System.Drawing.Font("Poppins Black", 10.8F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.startupBtn.ForeColor = System.Drawing.Color.White;
            this.startupBtn.Location = new System.Drawing.Point(69, 18);
            this.startupBtn.Name = "startupBtn";
            this.startupBtn.Size = new System.Drawing.Size(250, 70);
            this.startupBtn.TabIndex = 1;
            this.startupBtn.Text = "ADD THIS APP TO\r\nRUN AS START UP";
            this.startupTooltip.SetToolTip(this.startupBtn, "Starts scanning every 30 seconds and notifies if any bypass is detected.");
            this.startupBtn.UseVisualStyleBackColor = false;
            this.startupBtn.Click += new System.EventHandler(this.startupBtn_Click);
            // 
            // infoTxt
            // 
            this.infoTxt.BackColor = System.Drawing.Color.White;
            this.infoTxt.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.infoTxt.Cursor = System.Windows.Forms.Cursors.Arrow;
            this.infoTxt.Font = new System.Drawing.Font("Cascadia Code SemiBold", 10.2F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(163)));
            this.infoTxt.ForeColor = System.Drawing.Color.Chocolate;
            this.infoTxt.Location = new System.Drawing.Point(12, 358);
            this.infoTxt.Multiline = true;
            this.infoTxt.Name = "infoTxt";
            this.infoTxt.ReadOnly = true;
            this.infoTxt.Size = new System.Drawing.Size(466, 23);
            this.infoTxt.TabIndex = 1;
            this.infoTxt.Text = "AMSI Bypass Techniques that can be detected:";
            // 
            // pictureBox1
            // 
            this.pictureBox1.Image = global::AMSI_Detector_GUI.Properties.Resources.ChatGPT_Image_21_58_13_30_thg_5__2025;
            this.pictureBox1.Location = new System.Drawing.Point(-2, 1);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(485, 351);
            this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureBox1.TabIndex = 3;
            this.pictureBox1.TabStop = false;
            // 
            // textBox1
            // 
            this.textBox1.BackColor = System.Drawing.Color.White;
            this.textBox1.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox1.Cursor = System.Windows.Forms.Cursors.Arrow;
            this.textBox1.Font = new System.Drawing.Font("Cascadia Code SemiBold", 10.2F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(163)));
            this.textBox1.ForeColor = System.Drawing.Color.ForestGreen;
            this.textBox1.Location = new System.Drawing.Point(12, 382);
            this.textBox1.Multiline = true;
            this.textBox1.Name = "textBox1";
            this.textBox1.ReadOnly = true;
            this.textBox1.Size = new System.Drawing.Size(463, 90);
            this.textBox1.TabIndex = 4;
            this.textBox1.Text = "+ MpOav.dll patching\r\n+ amsiInitFailed override\r\n+ amsiContext corruption\r\n+ Scan" +
    "Content method swap";
            // 
            // textBox2
            // 
            this.textBox2.BackColor = System.Drawing.Color.White;
            this.textBox2.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox2.Cursor = System.Windows.Forms.Cursors.Arrow;
            this.textBox2.Font = new System.Drawing.Font("Cascadia Code SemiBold", 10.2F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(163)));
            this.textBox2.ForeColor = System.Drawing.Color.MidnightBlue;
            this.textBox2.Location = new System.Drawing.Point(12, 472);
            this.textBox2.Multiline = true;
            this.textBox2.Name = "textBox2";
            this.textBox2.ReadOnly = true;
            this.textBox2.Size = new System.Drawing.Size(466, 23);
            this.textBox2.TabIndex = 5;
            this.textBox2.Text = "Last updated 30/05/2025";
            // 
            // panel1
            // 
            this.panel1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(0)))), ((int)(((byte)(64)))));
            this.panel1.Controls.Add(this.textBox4);
            this.panel1.Controls.Add(this.startupBtn);
            this.panel1.Location = new System.Drawing.Point(482, 241);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(385, 258);
            this.panel1.TabIndex = 1;
            // 
            // textBox4
            // 
            this.textBox4.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(0)))), ((int)(((byte)(64)))));
            this.textBox4.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox4.Cursor = System.Windows.Forms.Cursors.Arrow;
            this.textBox4.Font = new System.Drawing.Font("Cascadia Code", 10.8F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(163)));
            this.textBox4.ForeColor = System.Drawing.Color.White;
            this.textBox4.Location = new System.Drawing.Point(13, 99);
            this.textBox4.Multiline = true;
            this.textBox4.Name = "textBox4";
            this.textBox4.ReadOnly = true;
            this.textBox4.Size = new System.Drawing.Size(362, 143);
            this.textBox4.TabIndex = 7;
            this.textBox4.Text = "- Real-time Monitoring (Startup Option)\r\n- Enable background monitoring of AMSI b" +
    "ypass attempts. Automatically starts with Windows if enabled.";
            // 
            // panel2
            // 
            this.panel2.BackColor = System.Drawing.Color.MidnightBlue;
            this.panel2.Location = new System.Drawing.Point(-2, -1);
            this.panel2.Name = "panel2";
            this.panel2.Size = new System.Drawing.Size(485, 354);
            this.panel2.TabIndex = 6;
            // 
            // AMSIDetector
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.White;
            this.ClientSize = new System.Drawing.Size(863, 499);
            this.Controls.Add(this.textBox2);
            this.Controls.Add(this.textBox1);
            this.Controls.Add(this.infoTxt);
            this.Controls.Add(this.choosePnl);
            this.Controls.Add(this.panel1);
            this.Controls.Add(this.pictureBox1);
            this.Controls.Add(this.panel2);
            this.Font = new System.Drawing.Font("Cascadia Code", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(163)));
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.Name = "AMSIDetector";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "AMSI Detector";
            this.choosePnl.ResumeLayout(false);
            this.choosePnl.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Panel choosePnl;
        private System.Windows.Forms.Button scanBtn;
        private System.Windows.Forms.Button startupBtn;
        private System.Windows.Forms.TextBox infoTxt;
        private System.Windows.Forms.PictureBox pictureBox1;
        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.TextBox textBox2;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.TextBox textBox3;
        private System.Windows.Forms.TextBox textBox4;
        private System.Windows.Forms.Panel panel2;
        private System.Windows.Forms.ToolTip scanTooltip;
        private System.Windows.Forms.ToolTip startupTooltip;
    }
}

