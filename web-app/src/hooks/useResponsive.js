import { useState, useEffect } from "react";

/**
 * Returns responsive breakpoint flags based on window width.
 * isMobile  < 640px   (iPhone SE → iPhone Pro Max)
 * isTablet  640-1023px (iPad)
 * isDesktop 1024px+
 */
export function useResponsive() {
  const [width, setWidth] = useState(
    typeof window !== "undefined" ? window.innerWidth : 1024
  );

  useEffect(() => {
    const handler = () => setWidth(window.innerWidth);
    window.addEventListener("resize", handler, { passive: true });
    return () => window.removeEventListener("resize", handler);
  }, []);

  return {
    width,
    isMobile:  width < 640,
    isTablet:  width >= 640 && width < 1024,
    isDesktop: width >= 1024,
  };
}
