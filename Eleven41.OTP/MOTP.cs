using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Eleven41.OTP
{
	// Implementation of Mobile OTP
	// http://motp.sourceforge.net/

	public class MOTP
	{
		private const int EpochWindow = 18;

		private static List<UsedPassword> _usedPasswords;

		static MOTP()
		{
			_usedPasswords = new List<UsedPassword>();
		}

		protected static string GetMD5Hash(string value)
		{
			byte[] buffer = System.Text.Encoding.ASCII.GetBytes(value);

			MD5 md5 = new MD5CryptoServiceProvider();
			byte[] retVal = md5.ComputeHash(buffer);

			string s = BitConverter.ToString(retVal);
			return s.Replace("-", "").ToLower();
		}

		public bool Verify(string username, string password, string secret, string pin, int offset)
		{
			if (String.IsNullOrEmpty(username))
				return false;
			if (String.IsNullOrEmpty(password))
				return false;
			if (String.IsNullOrEmpty(secret))
				return false;
			if (String.IsNullOrEmpty(pin))
				return false;

			// Check for a used password
			lock (_usedPasswords)
			{
				var used = (from u in _usedPasswords
							where u.Password == password
							select u).Count();
				if (used > 0)
					return false;

				// Delete anything old
				DateTime utcOld = DateTime.UtcNow.AddMinutes(-20);
				var toDelete = (from u in _usedPasswords
								where u.Used < utcOld
								select u).ToArray();
				foreach (var u in toDelete)
					_usedPasswords.Remove(u);
			}


			username = Regex.Replace(username, @"[^0-9a-zA-Z._-]", "X");
			password = Regex.Replace(password, @"[^0-9a-f]", "0");
			secret = Regex.Replace(secret, @"[^0-9a-f]", "0");
			pin = Regex.Replace(pin, @"[^0-9]", "0");

			int nEpoch = this.Epoch;

			// Try the 3 minutes before and 3 minutes after the current epoch time
			for (int i = -EpochWindow; i <= EpochWindow; ++i)
			{
				int nEpochToTry = nEpoch + i;

				string s = String.Format("{0}{1}{2}", nEpochToTry, secret, pin);

				string checksum = GetMD5Hash(s).Substring(0, 6);
				if (checksum == password)
				{
					lock (_usedPasswords)
					{
						_usedPasswords.Add(new UsedPassword()
						{
							Username = username,
							Password = password,
							Used = DateTime.UtcNow
						});
					}
					return true;
				}
			}

			return false;
		}

		public int Epoch
		{
			get
			{
				DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
				DateTime utcNow = DateTime.UtcNow;
				TimeSpan diff = utcNow - epoch;
				int nEpoch = Convert.ToInt32(diff.TotalSeconds);
				nEpoch = nEpoch / 10;
				return nEpoch;
			}
		}
	}

	internal class UsedPassword
	{
		public string Username { get; set; }
		public string Password { get; set; }
		public DateTime Used { get; set; }
	}
}
