import { LogLevel, type Configuration } from "@azure/msal-browser";

const tenantId = import.meta.env.VITE_ENTRA_TENANT_ID as string;
const webClientId = import.meta.env.VITE_ENTRA_WEB_CLIENT_ID as string;
const apiClientId = import.meta.env.VITE_ENTRA_API_CLIENT_ID as string;

export const msalConfig: Configuration = {
    auth: {
        clientId: webClientId,
        authority: `https://login.microsoftonline.com/${tenantId}`,
        redirectUri: window.location.origin,
        postLogoutRedirectUri: window.location.origin,
    },
    cache: {
        cacheLocation: "localStorage",
    },
    system: {
        loggerOptions: {
            loggerCallback: (level, message, containsPii) => {
                if (containsPii) return;
                if (level === LogLevel.Error) console.error(message);
                if (level === LogLevel.Warning) console.warn(message);
                if (level === LogLevel.Info) console.info(message);
                if (level === LogLevel.Verbose) console.debug(message);
            },
            logLevel: LogLevel.Warning,
        },
    },
};

// Scope you created: access_as_user
export const loginRequest = {
    scopes: [`api://${apiClientId}/access_as_user`],
};
