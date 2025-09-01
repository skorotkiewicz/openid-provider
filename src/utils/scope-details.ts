// Helper function to get scope details
export function getScopeDetails(scopes: string[]) {
  const scopeInfo: {
    [key: string]: { title: string; description: string; icon: string };
  } = {
    openid: {
      title: "Sign you in",
      description: "Allow this application to identify you",
      icon: "👤",
    },
    email: {
      title: "Access your email",
      description: "Read your email address",
      icon: "📧",
    },
    name: {
      title: "Access your name",
      description: "Read your full name",
      icon: "🏷️",
    },
    about: {
      title: "Access your bio",
      description: "Read your about information",
      icon: "📝",
    },
    website: {
      title: "Access your website",
      description: "Read your website URL",
      icon: "🌐",
    },
    twitter: {
      title: "Access your Twitter",
      description: "Read your Twitter username",
      icon: "🐦",
    },
    github: {
      title: "Access your GitHub",
      description: "Read your GitHub username",
      icon: "💻",
    },
    // Keep profile for backward compatibility
    profile: {
      title: "Access your full profile",
      description: "Read your name, about info, website, and social profiles",
      icon: "📋",
    },
  };

  return scopes.map(
    (scope) =>
      scopeInfo[scope] || {
        title: scope,
        description: "Custom permission",
        icon: "🔧",
      },
  );
}
