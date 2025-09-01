interface Context {
  req: {
    header: (name: string) => string | undefined; //
  };
}

export const baseUrl = (c: Context) => {
  const host = c.req.header("host") || "localhost:3000";
  const protocol = host.includes("localhost") ? "http" : "https";
  return `${protocol}://${host}`;
};
