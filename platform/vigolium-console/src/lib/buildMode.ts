export const BUILD_MODE = process.env.NEXT_PUBLIC_BUILD_MODE || 'cloud';
export const isStaticBuild = BUILD_MODE === 'static';
export const isCloudBuild = BUILD_MODE === 'cloud';
