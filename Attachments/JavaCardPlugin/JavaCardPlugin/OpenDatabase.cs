using System;
using System.Security.Cryptography;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassLib.Keys;


namespace JavaCardPlugin
{

	
	public sealed class JavaCardPluginExt : Plugin
	{
		private IPluginHost m_host = null;
		private SampleKeyProvider m_prov = new SampleKeyProvider();
		

		public override bool Initialize(IPluginHost host)
		{
			
			if (host == null) return false;
			m_host = host;
			m_host.KeyProviderPool.Add(m_prov);

		
			return true;
		}

		public override void Terminate()
		{
			m_host.KeyProviderPool.Remove(m_prov);
			
		}

		
		public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
		{
			// Provide a menu item for the main location(s)
			if (t == PluginMenuType.Main)
			{
				ToolStripMenuItem tsmi = new ToolStripMenuItem();
				tsmi.Text = "Change Pin";
				tsmi.Click += this.OnOptionsClicked;
				return tsmi;
			}

			if(t == PluginMenuType.Entry)
            {
				ToolStripMenuItem button = new ToolStripMenuItem();
				button.Text = "Invalidate Database Key";
				button.Click += this.ClickToReset;
				return button;
			}
			return null; // No menu items in other locations
		}


		private void ClickToReset(object sender, EventArgs e)
		{
			JavaCard t = new JavaCard();
			if (t.SelectApplet() == false)
			{
				string a = "No reader detected";
				MessageBox.Show(a, "Error");
				return;
			}

			if (t.EstablishSecureChannel() == false)
			{
				return;
			}

			if (t.UnlockCard() == false)
			{
				string a = "Incorrect pin";
				MessageBox.Show(a, "Error");
				return;
			}

			if (t.InvalidateDatabaseKey() == true)
			{
				MessageBox.Show("The key has been ivalidated", "Success!");
			}
			else
			{
				MessageBox.Show("The database key is still active", "Error!");
			}
		}

		private void OnOptionsClicked(object sender, EventArgs e)
		{
			JavaCard t = new JavaCard();
			if (t.SelectApplet() == false)
			{
				string a = "No reader detected";
				MessageBox.Show(a, "Error");
				return;
			}

			if (t.EstablishSecureChannel() == false)
			{
				return;
			}

			if (t.UnlockCard() == false)
			{
				string a = "Incorrect pin";
				MessageBox.Show(a, "Error");
				return;
			}

			if(t.ChangePin() == true)
            {
				MessageBox.Show("Pin changed", "Success!");
            }
            else
            {
				MessageBox.Show("Pin did not change.", "Error!");
			}
		}

		public sealed class SampleKeyProvider : KeyProvider
		{
			private JavaCard t;
			byte[] buff = null;
			public override string Name
			{
				get { return "JavaCard Plugin"; }
			}
            ~SampleKeyProvider()
            {
				if (buff != null)
				{
					for (int i = 0; i < buff.Length; i++)
					{
						buff[i] = 0;
					}
				}
				
				if(t != null)
                {
					GC.Collect();
                }
            }




			public override byte[] GetKey(KeyProviderQueryContext ctx)
			{
				t = new JavaCard();
				
				if (t.SelectApplet() == false)
                {
					string a = "No reader detected";
					MessageBox.Show(a, "Error");
					return buff;
				}


				if (t.EstablishSecureChannel() == false)
                {
					return buff;
                }


				if (t.UnlockCard() == false)
                {
					string a = "Incorrect pin";
					MessageBox.Show(a, "Error");
					return buff;
				}

				
                if (t.reader == false)
                {
					string a = "Incorrect Key";
					MessageBox.Show(a, "Error");
					return buff;
                }
				//t.sendarr();
				buff = t.GetRSAKey();
				return buff;
			}

			/*	public override TextBox MassageBox(PluginMenuType t)
				{
					// Provide a menu item for the main location(s)
					if (t == PluginMenuType.Main)
					{
						ToolStripMenuItem tsmi = new ToolStripMenuItem();
						tsmi.Text = "Abcd Options";
						tsmi.Click += this.OnOptionsClicked;
						return tsmi;
					}

					return null; // No menu items in other locations
				}*/





		}
	}
}

