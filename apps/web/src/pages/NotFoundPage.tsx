import { Radar } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

export default function NotFoundPage() {
  const { t } = useTranslation();
  return <div className="not-found"><span><Radar size={34} /></span><div className="error-code">404</div><h1>{t("notFound.title")}</h1><p>{t("notFound.text")}</p><Link className="button primary" to="/soc">{t("notFound.action")}</Link></div>;
}
