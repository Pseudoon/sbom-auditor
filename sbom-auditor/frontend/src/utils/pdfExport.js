import jsPDF from 'jspdf';

export const generatePDFReport = async (result, projectName) => {
  try {
    const pdf = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4'
    });

    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    const leftMargin = 20;
    const rightMargin = 20;
    const contentWidth = pageWidth - leftMargin - rightMargin;
    let yPosition = 30;

    // ==================== HELPER FUNCTIONS ====================
    const addHeader = () => {
      // Background header
      pdf.setFillColor(59, 130, 246);
      pdf.rect(0, 0, pageWidth, 22, 'F');

      // Title
      pdf.setFontSize(22);
      pdf.setTextColor(255, 255, 255);
      pdf.text('SBOM AUDIT REPORT', pageWidth / 2, 15, { align: 'center' });
    };

    const addFooter = (currentPage, totalPages) => {
      pdf.setFontSize(7);
      pdf.setTextColor(150, 150, 150);
      pdf.text(
        `Page ${currentPage} of ${totalPages}`,
        leftMargin,
        pageHeight - 8
      );
      pdf.text(
        `Advanced SBOM Auditor • ${new Date().toLocaleDateString()}`,
        pageWidth / 2,
        pageHeight - 8,
        { align: 'center' }
      );
      pdf.text(
        `Confidential`,
        pageWidth - rightMargin,
        pageHeight - 8,
        { align: 'right' }
      );
    };

    const addSectionTitle = (title, yPos) => {
      pdf.setFontSize(13);
      pdf.setTextColor(59, 130, 246);
      pdf.text(title, leftMargin, yPos);
      
      // Underline
      pdf.setDrawColor(59, 130, 246);
      pdf.line(leftMargin, yPos + 2, pageWidth - rightMargin, yPos + 2);
      
      return yPos + 10;
    };

    const checkPageBreak = (neededSpace) => {
      if (yPosition + neededSpace > pageHeight - 20) {
        pdf.addPage();
        addHeader();
        yPosition = 30;
        return true;
      }
      return false;
    };

    // ==================== PAGE 1 ====================
    addHeader();
    yPosition = 28;

    // Project Info Box
    pdf.setFillColor(240, 245, 255);
    pdf.rect(leftMargin, yPosition, contentWidth, 16, 'F');
    pdf.setFontSize(10);
    pdf.setTextColor(60, 60, 60);
    pdf.text(`Project: ${projectName}`, leftMargin + 5, yPosition + 5);
    pdf.text(`Generated: ${new Date().toLocaleString()}`, leftMargin + 5, yPosition + 12);
    
    yPosition += 24;

    // Risk Score Section
    yPosition = addSectionTitle('RISK ASSESSMENT', yPosition);

    const summary = result.summary;
    const riskColor = summary.riskScore > 70 ? [220, 38, 38] : summary.riskScore > 40 ? [234, 88, 12] : [34, 197, 94];
    const riskLevel = summary.riskScore > 70 ? 'CRITICAL' : summary.riskScore > 40 ? 'HIGH' : 'LOW';

    // Risk Score Box - LEFT SIDE
    pdf.setDrawColor(...riskColor);
    pdf.setFillColor(...riskColor);
    pdf.rect(leftMargin, yPosition + 2, 35, 24, 'F');
    pdf.setTextColor(255, 255, 255);
    pdf.setFontSize(28);
    pdf.text(`${summary.riskScore}`, leftMargin + 17.5, yPosition + 15, { align: 'center' });

    pdf.setFontSize(9);
    pdf.text(`/100`, leftMargin + 17.5, yPosition + 21, { align: 'center' });

    // Risk Details - RIGHT SIDE (separated from box)
    pdf.setTextColor(0, 0, 0);
    pdf.setFontSize(9);
    pdf.text(`Risk Level: ${riskLevel}`, leftMargin + 42, yPosition + 2);

    pdf.setFontSize(8);
    pdf.setTextColor(80, 80, 80);
    
    const riskDetails = [
      `Dependencies: ${summary.totalDependencies}`,
      `Vulnerabilities: ${summary.totalVulnerabilities}`,
      `Critical: ${summary.critical}`,
      `High: ${summary.high}`,
      `Moderate: ${summary.moderate}`,
      `Low: ${summary.low}`
    ];

    let detailY = yPosition + 8;
    let column = 0;
    riskDetails.forEach((text, idx) => {
      if (idx === 3) {
        column = 1;
        detailY = yPosition + 8;
      }
      const xPos = column === 0 ? leftMargin + 42 : leftMargin + 95;
      pdf.text(text, xPos, detailY);
      detailY += 5;
    });

    yPosition += 32;

    // Vulnerability Summary - 4 Boxes
    checkPageBreak(25);
    yPosition = addSectionTitle('VULNERABILITY SUMMARY', yPosition);

    const severities = [
      { label: 'CRITICAL', count: summary.critical, color: [220, 38, 38] },
      { label: 'HIGH', count: summary.high, color: [249, 115, 22] },
      { label: 'MODERATE', count: summary.moderate, color: [234, 179, 8] },
      { label: 'LOW', count: summary.low, color: [34, 197, 94] }
    ];

    let boxX = leftMargin;
    severities.forEach(sev => {
      pdf.setFillColor(...sev.color);
      pdf.rect(boxX, yPosition, 32, 18, 'F');
      
      pdf.setTextColor(255, 255, 255);
      pdf.setFontSize(16);
      pdf.text(sev.count.toString(), boxX + 16, yPosition + 10, { align: 'center' });
      
      pdf.setFontSize(8);
      pdf.text(sev.label, boxX + 16, yPosition + 15, { align: 'center' });
      
      boxX += 36;
    });

    yPosition += 26;

    // Top Vulnerabilities
    if (result.vulnerabilities.length > 0) {
      yPosition += 4;
      checkPageBreak(30);
      yPosition = addSectionTitle('TOP VULNERABILITIES', yPosition);

      pdf.setFontSize(8.5);
      const topVulns = result.vulnerabilities.slice(0, 6);
      
      topVulns.forEach((vuln, idx) => {
        const severityColor = 
          vuln.severity === 'critical' ? [220, 38, 38] :
          vuln.severity === 'high' ? [249, 115, 22] :
          vuln.severity === 'moderate' ? [234, 179, 8] : [34, 197, 94];

        pdf.setTextColor(...severityColor);
        pdf.text(`${idx + 1}. ${vuln.name}`, leftMargin + 5, yPosition);
        
        pdf.setTextColor(100, 100, 100);
        pdf.setFontSize(7.5);
        const desc = vuln.description.length > 65 ? vuln.description.substring(0, 65) + '...' : vuln.description;
        pdf.text(`   ${vuln.severity.toUpperCase()} • ${desc}`, leftMargin + 5, yPosition + 3.5);
        
        const fixText = vuln.fixAvailable === 'yes' ? '✓ Fix available' : '✗ No fix yet';
        pdf.text(`   ${fixText}`, leftMargin + 5, yPosition + 6.5);
        
        yPosition += 9;
        pdf.setFontSize(8.5);
      });

      if (result.vulnerabilities.length > 6) {
        pdf.setTextColor(100, 100, 100);
        pdf.setFontSize(7.5);
        yPosition += 1;
        pdf.text(`... and ${result.vulnerabilities.length - 6} more vulnerabilities`, leftMargin + 5, yPosition);
      }
    }

    yPosition += 6;

    // Signature Verification
    if (result.signatures) {
      checkPageBreak(18);
      yPosition = addSectionTitle('SIGNATURE VERIFICATION', yPosition);

      const sigColor = result.signatures.status === 'full' ? [34, 197, 94] : result.signatures.status === 'partial' ? [234, 179, 8] : [220, 38, 38];
      pdf.setFillColor(...sigColor);
      pdf.rect(leftMargin, yPosition + 1, contentWidth, 10, 'F');

      pdf.setTextColor(255, 255, 255);
      pdf.setFontSize(9);
      pdf.text(`Status: ${result.signatures.status.toUpperCase()} | Verified: ${result.signatures.verifiedCount}/${result.signatures.totalPackages}`, leftMargin + 5, yPosition + 6);

      yPosition += 14;
    }

    // ==================== PAGE 2 ====================
    pdf.addPage();
    addHeader();
    yPosition = 30;

    // Dependencies List
    yPosition = addSectionTitle('DEPENDENCIES', yPosition);

    pdf.setFontSize(7.5);
    pdf.setTextColor(60, 60, 60);

    // Table header with better spacing
    pdf.setFillColor(220, 220, 220);
    pdf.rect(leftMargin, yPosition - 3, contentWidth, 6, 'F');
    pdf.setTextColor(0, 0, 0);
    pdf.setFontSize(8);
    pdf.text('Package', leftMargin + 2, yPosition + 1);
    pdf.text('Version', leftMargin + 70, yPosition + 1);
    pdf.text('Type', leftMargin + 105, yPosition + 1);
    pdf.text('Vulns', leftMargin + 155, yPosition + 1);

    yPosition += 10;

    const topDeps = result.dependencies.slice(0, 28);
    topDeps.forEach((dep) => {
      if (yPosition > pageHeight - 25) {
        pdf.addPage();
        addHeader();
        yPosition = 30;
      }

      pdf.setTextColor(60, 60, 60);
      pdf.setFontSize(7.5);
      
      const vulnColor = dep.vulnerabilities > 0 ? [220, 38, 38] : [34, 197, 94];
      pdf.setTextColor(...vulnColor);
      
      pdf.text(dep.name.substring(0, 35), leftMargin + 2, yPosition);
      pdf.text(`v${dep.version}`, leftMargin + 70, yPosition);
      pdf.text(dep.type, leftMargin + 105, yPosition);
      pdf.text(dep.vulnerabilities.toString(), leftMargin + 155, yPosition);
      
      yPosition += 5;
    });

    if (result.dependencies.length > 28) {
      pdf.setTextColor(100, 100, 100);
      pdf.setFontSize(7.5);
      yPosition += 2;
      pdf.text(`... and ${result.dependencies.length - 28} more dependencies`, leftMargin + 2, yPosition);
    }

    yPosition += 8;

    // Recommendations
    checkPageBreak(20);
    yPosition = addSectionTitle('RECOMMENDATIONS', yPosition);

    pdf.setFontSize(8);
    pdf.setTextColor(60, 60, 60);

    const recommendations = [];
    if (summary.critical > 0) {
      recommendations.push({
        text: `${summary.critical} CRITICAL vulnerabilities found`,
        subtext: 'Immediate action required'
      });
    }
    if (summary.high > 0) {
      recommendations.push({
        text: `${summary.high} HIGH severity vulnerabilities`,
        subtext: 'Fix within 1-2 weeks'
      });
    }
    if (summary.moderate > 0) {
      recommendations.push({
        text: `${summary.moderate} MODERATE vulnerabilities`,
        subtext: 'Plan updates within 1 month'
      });
    }
    
    if (recommendations.length === 0) {
      pdf.setFillColor(240, 250, 240);
      pdf.rect(leftMargin, yPosition, contentWidth, 12, 'F');
      pdf.setTextColor(34, 197, 94);
      pdf.setFontSize(9);
      pdf.text('✓ No critical vulnerabilities detected', leftMargin + 5, yPosition + 4);
      pdf.setTextColor(100, 100, 100);
      pdf.setFontSize(8);
      pdf.text('Your project has a good security posture', leftMargin + 5, yPosition + 9);
      yPosition += 16;
    } else {
      recommendations.forEach((rec, idx) => {
        const bgColor = 
          summary.critical > 0 && idx === 0 ? [255, 240, 240] :
          summary.high > 0 && idx <= 1 ? [255, 250, 235] : [255, 252, 240];
        
        pdf.setFillColor(...bgColor);
        pdf.rect(leftMargin, yPosition, contentWidth, 13, 'F');
        
        pdf.setTextColor(60, 60, 60);
        pdf.setFontSize(8.5);
        pdf.text(rec.text, leftMargin + 5, yPosition + 4);
        
        pdf.setTextColor(120, 120, 120);
        pdf.setFontSize(7.5);
        pdf.text(rec.subtext, leftMargin + 5, yPosition + 9);
        
        yPosition += 15;
      });
    }

    yPosition += 2;

    // Action Items
    checkPageBreak(18);
    yPosition = addSectionTitle('ACTION ITEMS', yPosition);

    pdf.setFontSize(8);
    pdf.setTextColor(60, 60, 60);

    const actions = [
      'Review all vulnerabilities in detail',
      'Update vulnerable packages to patched versions',
      'Run scan again after updates to verify fixes',
      'Enable continuous monitoring on CI/CD pipeline'
    ];

    actions.forEach((action, idx) => {
      // Numbered circle background
      pdf.setFillColor(59, 130, 246);
      pdf.circle(leftMargin + 4, yPosition + 1, 3);
      
      // Number
      pdf.setTextColor(255, 255, 255);
      pdf.setFontSize(7);
      pdf.text((idx + 1).toString(), leftMargin + 4, yPosition + 1.5, { align: 'center' });
      
      // Text
      pdf.setTextColor(60, 60, 60);
      pdf.setFontSize(8);
      pdf.text(action, leftMargin + 12, yPosition);
      
      yPosition += 8;
    });

    // ==================== ADD FOOTERS ====================
    const totalPages = pdf.internal.pages.length - 1;
    for (let i = 1; i <= totalPages; i++) {
      pdf.setPage(i);
      addFooter(i, totalPages);
    }

    // Save PDF
    const fileName = `SBOM-Report-${projectName.replace(/\s+/g, '-')}-${new Date().toISOString().split('T')[0]}.pdf`;
    pdf.save(fileName);

    console.log('✓ Professional PDF generated:', fileName);
  } catch (error) {
    console.error('PDF error:', error);
    alert('PDF Error: ' + error.message);
    throw error;
  }
};
