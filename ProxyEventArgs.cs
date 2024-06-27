using Titanium.Web.Proxy.EventArguments;

namespace GroboldProxy
{
    public static class ProxyEventArgs
    {
        public static ClientState GetState(this ProxyEventArgsBase args)
        {
            if (args.ClientUserData == null) args.ClientUserData = new ClientState();

            return (ClientState)args.ClientUserData;
        }
    }
}