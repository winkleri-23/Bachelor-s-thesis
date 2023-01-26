using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using PCSC;
using PCSC.Iso7816;




public class Form1 : Form
{
    private TextBox textBox1;

    public Form1()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {

       
        string message1 = "Simple MessageBox";
        string title1 = "sds";
       
        MessageBox.Show(message1, title1);
    }
   
}