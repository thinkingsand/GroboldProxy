using System;
using Titanium.Web.Proxy.Helpers;

namespace GroboldProxy
{
    public class Program
    {
        private static readonly ProxyController controller = new ProxyController();

        public static void Main(string[] args)
        {
            if (RunTime.IsWindows)
                // fix console hang due to QuickEdit mode
                ConsoleHelper.DisableQuickEditMode();

            // Start proxy controller
            controller.StartProxy();

            Console.WriteLine("Hit any key to exit..");
            Console.WriteLine();
            Console.Read();

            controller.Stop();
        }
    }
}