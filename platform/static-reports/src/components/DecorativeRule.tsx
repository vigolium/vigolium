interface Props {
  variant?: "single" | "double" | "ornamental";
  className?: string;
}

export default function DecorativeRule({ variant = "single", className = "" }: Props) {
  const ruleClass = {
    single: "rule-single",
    double: "rule-double",
    ornamental: "rule-ornamental",
  }[variant];

  return <hr className={`${ruleClass} my-4 ${className}`} />;
}
