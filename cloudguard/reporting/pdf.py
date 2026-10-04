from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from cloudguard.reporting.models import (
    SecurityReport,
)


class SecurityReportPDF:
    """
    Renders CloudGuard's structured SecurityReport
    as a professional PDF document.

    The renderer does not perform security analysis.
    It only presents evidence already produced by
    CloudGuard's analysis pipeline.
    """

    def __init__(self) -> None:
        self.page_width, self.page_height = A4

        self.background = colors.HexColor(
            "#FFFFFF"
        )
        self.text = colors.HexColor(
            "#172033"
        )
        self.muted = colors.HexColor(
            "#667085"
        )
        self.border = colors.HexColor(
            "#D9E0EA"
        )
        self.panel = colors.HexColor(
            "#F7F9FC"
        )
        self.blue = colors.HexColor(
            "#315FDB"
        )
        self.critical = colors.HexColor(
            "#C9344D"
        )
        self.high = colors.HexColor(
            "#C46B24"
        )
        self.medium = colors.HexColor(
            "#9A7417"
        )
        self.low = colors.HexColor(
            "#356FAF"
        )

        self.styles = self._build_styles()

    def build(
        self,
        report: SecurityReport,
    ) -> bytes:
        """
        Build and return the complete PDF as bytes.
        """

        buffer = BytesIO()

        document = BaseDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=20 * mm,
            bottomMargin=18 * mm,
            title=report.report_name,
            author="CloudGuard",
            subject=(
                "Cloud security assessment report"
            ),
        )

        frame = Frame(
            document.leftMargin,
            document.bottomMargin,
            document.width,
            document.height,
            id="normal",
        )

        template = PageTemplate(
            id="cloudguard",
            frames=[frame],
            onPage=self._draw_page,
        )

        document.addPageTemplates(
            [template]
        )

        story = []

        story.extend(
            self._build_title(report)
        )

        story.extend(
            self._build_executive_summary(
                report
            )
        )

        story.extend(
            self._build_findings(report)
        )

        story.extend(
            self._build_attack_paths(report)
        )

        story.extend(
            self._build_identity_risks(
                report
            )
        )

        story.extend(
            self._build_network_risks(
                report
            )
        )

        story.extend(
            self._build_compliance(report)
        )

        story.extend(
            self._build_limitations(report)
        )

        document.build(story)

        pdf_bytes = buffer.getvalue()
        buffer.close()

        return pdf_bytes

    def _build_styles(self) -> dict:
        sample = getSampleStyleSheet()

        return {
            "title": ParagraphStyle(
                "CloudGuardTitle",
                parent=sample["Title"],
                fontName="Helvetica-Bold",
                fontSize=24,
                leading=29,
                textColor=self.text,
                spaceAfter=6,
            ),
            "subtitle": ParagraphStyle(
                "CloudGuardSubtitle",
                parent=sample["Normal"],
                fontName="Helvetica",
                fontSize=10,
                leading=15,
                textColor=self.muted,
                spaceAfter=10,
            ),
            "section": ParagraphStyle(
                "CloudGuardSection",
                parent=sample["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=15,
                leading=19,
                textColor=self.text,
                spaceBefore=12,
                spaceAfter=9,
            ),
            "subsection": ParagraphStyle(
                "CloudGuardSubsection",
                parent=sample["Heading3"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=15,
                textColor=self.text,
                spaceBefore=6,
                spaceAfter=5,
            ),
            "body": ParagraphStyle(
                "CloudGuardBody",
                parent=sample["BodyText"],
                fontName="Helvetica",
                fontSize=9,
                leading=14,
                textColor=self.text,
                spaceAfter=6,
            ),
            "muted": ParagraphStyle(
                "CloudGuardMuted",
                parent=sample["BodyText"],
                fontName="Helvetica",
                fontSize=8,
                leading=12,
                textColor=self.muted,
                spaceAfter=5,
            ),
            "small": ParagraphStyle(
                "CloudGuardSmall",
                parent=sample["BodyText"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=11,
                textColor=self.muted,
            ),
            "center": ParagraphStyle(
                "CloudGuardCenter",
                parent=sample["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=12,
                alignment=TA_CENTER,
                textColor=self.text,
            ),
        }

    def _build_title(
        self,
        report: SecurityReport,
    ) -> list:
        elements = [
            Spacer(1, 5 * mm),
            Paragraph(
                escape(report.report_name),
                self.styles["title"],
            ),
            Paragraph(
                (
                    "Evidence-based cloud security "
                    "assessment"
                ),
                self.styles["subtitle"],
            ),
        ]

        metadata = [
            [
                self._p("Report version"),
                self._p(
                    report.report_version,
                    bold=True,
                ),
                self._p("Assessment mode"),
                self._p(
                    report.assessment_mode.upper(),
                    bold=True,
                ),
            ]
        ]

        table = Table(
            metadata,
            colWidths=[
                32 * mm,
                42 * mm,
                34 * mm,
                42 * mm,
            ],
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        self.panel,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        self.border,
                    ),
                    (
                        "INNERGRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        self.border,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                ]
            )
        )

        elements.extend(
            [
                table,
                Spacer(1, 5 * mm),
                Paragraph(
                    "<b>Assessment scope</b>",
                    self.styles["subsection"],
                ),
                Paragraph(
                    escape(report.scope_note),
                    self.styles["body"],
                ),
                Spacer(1, 3 * mm),
            ]
        )

        return elements

    def _build_executive_summary(
        self,
        report: SecurityReport,
    ) -> list:
        summary = report.summary

        metric_data = [
            [
                self._metric(
                    "Highest Risk",
                    summary.highest_risk_score,
                ),
                self._metric(
                    "Critical",
                    summary.critical_findings,
                ),
                self._metric(
                    "High",
                    summary.high_findings,
                ),
            ],
            [
                self._metric(
                    "Attack Paths",
                    summary.attack_paths,
                ),
                self._metric(
                    "Exposed Assets",
                    summary.internet_exposed_assets,
                ),
                self._metric(
                    "Total Assets",
                    summary.total_assets,
                ),
            ],
        ]

        metrics = Table(
            metric_data,
            colWidths=[
                52 * mm,
                52 * mm,
                52 * mm,
            ],
        )

        metrics.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        self.panel,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        self.border,
                    ),
                    (
                        "INNERGRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        self.border,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                ]
            )
        )

        posture = [
            ["Metric", "Value"],
            [
                "Security relationships",
                str(summary.total_relationships),
            ],
            [
                "Sensitive assets",
                str(summary.sensitive_assets),
            ],
            [
                "Total findings",
                str(summary.findings),
            ],
            [
                "Medium findings",
                str(summary.medium_findings),
            ],
            [
                "Low findings",
                str(summary.low_findings),
            ],
            [
                "Informational findings",
                str(summary.info_findings),
            ],
        ]

        posture_table = Table(
            posture,
            colWidths=[
                110 * mm,
                46 * mm,
            ],
            repeatRows=1,
        )

        self._style_standard_table(
            posture_table
        )

        return [
            Paragraph(
                "Executive Summary",
                self.styles["section"],
            ),
            metrics,
            Spacer(1, 4 * mm),
            posture_table,
        ]

    def _build_findings(
        self,
        report: SecurityReport,
    ) -> list:
        elements = [
            Paragraph(
                "Prioritized Findings",
                self.styles["section"],
            )
        ]

        if not report.findings:
            elements.append(
                Paragraph(
                    "No findings were produced.",
                    self.styles["body"],
                )
            )
            return elements

        for finding in report.findings:
            severity_color = (
                self._severity_color(
                    finding.severity
                )
            )

            header = Table(
                [
                    [
                        Paragraph(
                            (
                                f"<b>{escape(finding.title)}</b>"
                                f"<br/><font size='7'>"
                                f"{escape(finding.id)}"
                                "</font>"
                            ),
                            self.styles["body"],
                        ),
                        Paragraph(
                            (
                                f"<b>{escape(finding.severity)}</b>"
                                f"<br/>Risk "
                                f"{finding.risk_score}/100"
                            ),
                            self.styles["center"],
                        ),
                    ]
                ],
                colWidths=[
                    126 * mm,
                    30 * mm,
                ],
            )

            header.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (0, 0),
                            self.panel,
                        ),
                        (
                            "BACKGROUND",
                            (1, 0),
                            (1, 0),
                            severity_color,
                        ),
                        (
                            "TEXTCOLOR",
                            (1, 0),
                            (1, 0),
                            colors.white,
                        ),
                        (
                            "BOX",
                            (0, 0),
                            (-1, -1),
                            0.6,
                            self.border,
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "MIDDLE",
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            8,
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            8,
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            7,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            7,
                        ),
                    ]
                )
            )

            block = [
                header,
                Spacer(1, 2 * mm),
                Paragraph(
                    escape(finding.description),
                    self.styles["body"],
                ),
                Paragraph(
                    "<b>Affected assets</b>",
                    self.styles["subsection"],
                ),
                Paragraph(
                    self._join_items(
                        finding.affected_assets
                    ),
                    self.styles["small"],
                ),
                Paragraph(
                    "<b>Evidence</b>",
                    self.styles["subsection"],
                ),
            ]

            for evidence in finding.evidence:
                block.append(
                    self._bullet(evidence)
                )

            block.extend(
                [
                    Paragraph(
                        "<b>Recommended remediation</b>",
                        self.styles["subsection"],
                    ),
                    Paragraph(
                        escape(
                            finding.remediation
                            or (
                                "No remediation guidance "
                                "is available."
                            )
                        ),
                        self.styles["body"],
                    ),
                    Spacer(1, 4 * mm),
                ]
            )

            elements.append(
                KeepTogether(block)
            )

        return elements

    def _build_attack_paths(
        self,
        report: SecurityReport,
    ) -> list:
        elements = [
            Paragraph(
                "Attack Path Analysis",
                self.styles["section"],
            )
        ]

        if not report.attack_paths:
            elements.append(
                Paragraph(
                    "No attack paths were discovered.",
                    self.styles["body"],
                )
            )
            return elements

        for index, path in enumerate(
            report.attack_paths,
            start=1,
        ):
            chain = "  →  ".join(
                escape(node)
                for node in path.nodes
            )

            elements.extend(
                [
                    Paragraph(
                        f"Attack Path {index}",
                        self.styles["subsection"],
                    ),
                    Paragraph(
                        chain,
                        self.styles["body"],
                    ),
                    Paragraph(
                        (
                            f"{path.hop_count} hops · "
                            f"Sensitive target: "
                            f"{'Yes' if path.sensitive_target else 'No'}"
                        ),
                        self.styles["muted"],
                    ),
                ]
            )

        return elements

    def _build_identity_risks(
        self,
        report: SecurityReport,
    ) -> list:
        elements = [
            Paragraph(
                "Identity & IAM Risk",
                self.styles["section"],
            )
        ]

        if not report.identity_risks:
            elements.append(
                Paragraph(
                    "No contextual identity risks "
                    "were identified.",
                    self.styles["body"],
                )
            )
            return elements

        for risk in report.identity_risks:
            data = [
                ["Identity", risk.identity_name],
                ["Type", risk.identity_type],
                [
                    "Risk",
                    (
                        f"{risk.risk_score}/100 "
                        f"({risk.severity.upper()})"
                    ),
                ],
                [
                    "Observed permissions",
                    ", ".join(risk.permissions)
                    or "None represented",
                ],
                [
                    "Exposed workloads",
                    ", ".join(
                        risk.exposed_workloads
                    )
                    or "None",
                ],
                [
                    "Sensitive resources",
                    ", ".join(
                        risk.sensitive_resources
                    )
                    or "None",
                ],
            ]

            table = Table(
                data,
                colWidths=[
                    43 * mm,
                    113 * mm,
                ],
            )

            self._style_standard_table(table)

            elements.append(table)
            elements.append(
                Spacer(1, 2 * mm)
            )

            elements.append(
                Paragraph(
                    "<b>Risk factors</b>",
                    self.styles["subsection"],
                )
            )

            for factor in risk.risk_factors:
                elements.append(
                    self._bullet(factor)
                )

            elements.append(
                Spacer(1, 3 * mm)
            )

        return elements

    def _build_network_risks(
        self,
        report: SecurityReport,
    ) -> list:
        elements = [
            Paragraph(
                "Network Exposure",
                self.styles["section"],
            )
        ]

        if not report.network_risks:
            elements.append(
                Paragraph(
                    "No contextual network risks "
                    "were identified.",
                    self.styles["body"],
                )
            )
            return elements

        for risk in report.network_risks:
            data = [
                ["Asset", risk.asset_name],
                [
                    "Public IP",
                    risk.public_ip
                    or "No public IP",
                ],
                [
                    "Risk",
                    (
                        f"{risk.risk_score}/100 "
                        f"({risk.severity.upper()})"
                    ),
                ],
                [
                    "Security groups",
                    ", ".join(
                        risk.security_groups
                    )
                    or "None",
                ],
                [
                    "Attached identities",
                    ", ".join(
                        risk.attached_identities
                    )
                    or "None",
                ],
                [
                    "Sensitive resources",
                    ", ".join(
                        risk.sensitive_resources
                    )
                    or "None",
                ],
            ]

            table = Table(
                data,
                colWidths=[
                    43 * mm,
                    113 * mm,
                ],
            )

            self._style_standard_table(table)

            elements.append(table)

            if risk.exposed_services:
                elements.append(
                    Paragraph(
                        "Exposed services",
                        self.styles["subsection"],
                    )
                )

                services = [
                    [
                        "Protocol",
                        "Ports",
                        "Source",
                        "Security Group",
                    ]
                ]

                for service in (
                    risk.exposed_services
                ):
                    from_port = service.get(
                        "from_port"
                    )
                    to_port = service.get(
                        "to_port"
                    )

                    if (
                        from_port is not None
                        and to_port is not None
                    ):
                        if from_port == to_port:
                            ports = str(
                                from_port
                            )
                        else:
                            ports = (
                                f"{from_port}-"
                                f"{to_port}"
                            )
                    else:
                        ports = "All/unknown"

                    services.append(
                        [
                            str(
                                service.get(
                                    "protocol",
                                    "",
                                )
                            ),
                            ports,
                            ", ".join(
                                service.get(
                                    "sources",
                                    [],
                                )
                            ),
                            str(
                                service.get(
                                    "security_group_name",
                                    "",
                                )
                            ),
                        ]
                    )

                services_table = Table(
                    services,
                    colWidths=[
                        25 * mm,
                        27 * mm,
                        46 * mm,
                        58 * mm,
                    ],
                    repeatRows=1,
                )

                self._style_standard_table(
                    services_table
                )

                elements.append(
                    services_table
                )

            elements.append(
                Paragraph(
                    "Risk factors",
                    self.styles["subsection"],
                )
            )

            for factor in risk.risk_factors:
                elements.append(
                    self._bullet(factor)
                )

            elements.append(
                Spacer(1, 3 * mm)
            )

        return elements

    def _build_compliance(
        self,
        report: SecurityReport,
    ) -> list:
        compliance = report.compliance

        elements = [
            Paragraph(
                "Compliance Mapping",
                self.styles["section"],
            ),
            Paragraph(
                (
                    "These mappings are evidence-based "
                    "security indicators. They do not "
                    "represent certification, "
                    "attestation, or a complete "
                    "framework audit."
                ),
                self.styles["muted"],
            ),
        ]

        summary = [
            ["Metric", "Value"],
            [
                "Frameworks",
                str(compliance.frameworks),
            ],
            [
                "Mapped controls",
                str(compliance.mapped_controls),
            ],
            [
                "Non-compliant controls",
                str(
                    compliance
                    .non_compliant_controls
                ),
            ],
            [
                "Not assessed",
                str(
                    compliance
                    .not_assessed_controls
                ),
            ],
            [
                "Mapped findings",
                str(compliance.mapped_findings),
            ],
        ]

        summary_table = Table(
            summary,
            colWidths=[
                110 * mm,
                46 * mm,
            ],
            repeatRows=1,
        )

        self._style_standard_table(
            summary_table
        )

        elements.extend(
            [
                summary_table,
                Spacer(1, 4 * mm),
            ]
        )

        if report.compliance_controls:
            controls = [
                [
                    "Framework",
                    "Control",
                    "Status",
                    "Title",
                ]
            ]

            for control in (
                report.compliance_controls
            ):
                controls.append(
                    [
                        str(
                            control.get(
                                "framework",
                                "",
                            )
                        ),
                        str(
                            control.get(
                                "control_id",
                                "",
                            )
                        ),
                        str(
                            control.get(
                                "status",
                                "",
                            )
                        ),
                        str(
                            control.get(
                                "title",
                                "",
                            )
                        ),
                    ]
                )

            controls_table = Table(
                controls,
                colWidths=[
                    35 * mm,
                    29 * mm,
                    30 * mm,
                    62 * mm,
                ],
                repeatRows=1,
            )

            self._style_standard_table(
                controls_table
            )

            elements.append(
                controls_table
            )

        return elements

    def _build_limitations(
        self,
        report: SecurityReport,
    ) -> list:
        elements = [
            Paragraph(
                "Assessment Limitations",
                self.styles["section"],
            )
        ]

        for limitation in report.limitations:
            elements.append(
                self._bullet(limitation)
            )

        elements.extend(
            [
                Spacer(1, 5 * mm),
                Paragraph(
                    (
                        "End of CloudGuard Security "
                        "Assessment"
                    ),
                    self.styles["muted"],
                ),
            ]
        )

        return elements

    def _draw_page(
        self,
        canvas,
        document,
    ) -> None:
        canvas.saveState()

        canvas.setFillColor(
            self.background
        )

        canvas.rect(
            0,
            0,
            self.page_width,
            self.page_height,
            fill=1,
            stroke=0,
        )

        canvas.setStrokeColor(
            self.border
        )

        canvas.line(
            18 * mm,
            14 * mm,
            self.page_width - 18 * mm,
            14 * mm,
        )

        canvas.setFillColor(
            self.muted
        )

        canvas.setFont(
            "Helvetica",
            7,
        )

        canvas.drawString(
            18 * mm,
            9 * mm,
            "CloudGuard Security Assessment",
        )

        page_number = (
            f"Page {document.page}"
        )

        canvas.drawRightString(
            self.page_width - 18 * mm,
            9 * mm,
            page_number,
        )

        canvas.restoreState()

    def _style_standard_table(
        self,
        table: Table,
    ) -> None:
        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        self.blue,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "BACKGROUND",
                        (0, 1),
                        (-1, -1),
                        colors.white,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 1),
                        (-1, -1),
                        self.text,
                    ),
                    (
                        "FONTNAME",
                        (0, 1),
                        (-1, -1),
                        "Helvetica",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        self.border,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

    def _metric(
        self,
        label: str,
        value: int,
    ) -> Paragraph:
        return Paragraph(
            (
                f"<font size='7' color='#667085'>"
                f"{escape(label.upper())}"
                f"</font>"
                f"<br/>"
                f"<font size='18'><b>"
                f"{value}"
                f"</b></font>"
            ),
            self.styles["center"],
        )

    def _bullet(
        self,
        text: str,
    ) -> Paragraph:
        return Paragraph(
            f"• {escape(text)}",
            self.styles["body"],
        )

    def _p(
        self,
        text: str,
        *,
        bold: bool = False,
    ) -> Paragraph:
        safe = escape(str(text))

        if bold:
            safe = f"<b>{safe}</b>"

        return Paragraph(
            safe,
            self.styles["small"],
        )

    @staticmethod
    def _join_items(
        values: list[str],
    ) -> str:
        if not values:
            return "None"

        return " · ".join(
            escape(value)
            for value in values
        )

    def _severity_color(
        self,
        severity: str,
    ):
        normalized = severity.lower()

        if normalized == "critical":
            return self.critical

        if normalized == "high":
            return self.high

        if normalized == "medium":
            return self.medium

        if normalized == "low":
            return self.low

        return self.blue