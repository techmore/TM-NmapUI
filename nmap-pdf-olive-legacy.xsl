<?xml version="1.0" encoding="utf-8"?>
<!--
Nmap Modern XSL
Updated with modern Tailwind styling and olive color scheme
This software must not be used by military or secret service organisations.
Original: Andreas Hontzia (@honze_net) & LRVT (@l4rm4nd)
Updated: 2026
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>
  
  <!-- Services that have both product and version -->
  <xsl:key name="svcByProduct"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="@product"/>

  <!-- Distinct Product|Version groups -->
  <xsl:key name="svcByProdVer"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version)"/>

  <!-- Distinct Product|Version|Host groups (for unique host counting) -->
  <xsl:key name="svcByProdVerHost"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version,'|', ancestor::host/address/@addr)"/>

  <!-- Distinct Product|Version|Host|Port groups (for host list with ports) -->
  <xsl:key name="svcByProdVerHostPort"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version,'|',
                       ancestor::host/address/@addr,'|',
                       ../@protocol,'|',../@portid)"/>
  
  <!-- All open SSH services (name="ssh") -->
  <xsl:key name="sshSvcs"
           match="nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']"
           use="1"/>

  <!-- Product|Version groups derived from HTTP titles like 'Apache Tomcat/7.0.54' -->
  <xsl:key name="httpTitleByProdVer"
           match="nmaprun/host/ports/port[state/@state='open' and @protocol='tcp']
                  /script[@id='http-title']/elem[@key='title'][contains(normalize-space(.), '/')]"
           use="concat(
                  substring-before(normalize-space(.), '/'),
                  '|',
                  substring-after(normalize-space(.), '/')
               )"/>

  <!-- Distinct Product|Version|Host|Port groups for HTTP-title based entries -->
  <xsl:key name="httpTitleByProdVerHostPort"
           match="nmaprun/host/ports/port[state/@state='open' and @protocol='tcp']
                  /script[@id='http-title']/elem[@key='title'][contains(normalize-space(.), '/')]"
           use="concat(
                  substring-before(normalize-space(.), '/'),
                  '|',
                  substring-after(normalize-space(.), '/'),
                  '|',
                  ancestor::host/address/@addr,
                  '|',
                  ancestor::port[1]/@protocol,
                  '|',
                  ancestor::port[1]/@portid
               )"/>           

  <xsl:template name="last-command-argument">
    <xsl:param name="arguments"/>
    <xsl:variable name="normalized" select="normalize-space($arguments)"/>
    <xsl:choose>
      <xsl:when test="contains($normalized, ' ')">
        <xsl:call-template name="last-command-argument">
          <xsl:with-param name="arguments" select="substring-after($normalized, ' ')"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise><xsl:value-of select="$normalized"/></xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta name="referrer" content="no-referrer"/>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <meta name="nmapui-report-policy" content="v1"/>
        <meta http-equiv="Content-Security-Policy" content="__NMAPUI_REPORT_CSP__"/>
        __NMAPUI_TAILWIND_CSS__
        
        <style>
          body {
            font-family: 'Inter', system-ui, sans-serif;
            background-color: #e9ebe0;
            color: #262724;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
          }
          
          h1, h2, h3, h4, h5 {
            font-family: 'Instrument Serif', serif;
          }
          
          ::selection {
            background-color: #bcc2a9;
            color: white;
          }
          
          .nav-link {
            position: relative;
            transition: color 0.2s ease;
          }
          
          .nav-link:hover {
            color: #636b54;
          }
          
          .nav-link::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 2px;
            background-color: #636b54;
            transition: width 0.2s ease;
          }
          
          .nav-link:hover::after {
            width: 100%;
          }
          
          /* #167 v2: keep wide tables inside the page */
          @media print {
            html, body { width: 100% !important; }
            .max-w-7xl { max-width: 100% !important; padding: 0 !important; }
            table { table-layout: auto; }
            th, td { font-size: 9px !important; padding: 3px 4px !important; }
            td, th { word-break: break-word; overflow-wrap: anywhere; }
            .font-mono, td.font-mono { word-break: break-all !important; }
            nav.fixed { position: static !important; }
          }

          .card {
            background: white;
            border: 1px solid #d8dbc7;
            border-radius: 12px;
            transition: all 0.2s ease;
          }
          
          .card:hover {
            border-color: #bcc2a9;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
          }
          
          .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
          }
          
          .badge-success {
            background-color: #979f83;
            color: white;
          }
          
          .badge-danger {
            background-color: #ef4444;
            color: white;
          }
          
          .badge-warning {
            background-color: #f59e0b;
            color: white;
          }
          
          table.dataTable {
            border-collapse: separate;
            border-spacing: 0;
            border: 1px solid #d8dbc7;
            border-radius: 12px;
            overflow: hidden;
          }
          
          table.dataTable thead th {
            background-color: #32382a;
            color: white;
            font-weight: 500;
            border: none;
            padding: 12px 16px;
          }
          
          table.dataTable tbody td {
            border-top: 1px solid #d8dbc7;
            padding: 12px 16px;
          }
          
          table.dataTable tbody tr:hover {
            background-color: #f5f6f3;
          }
          
          .dt-buttons {
            margin-bottom: 16px;
          }
          
          .dt-button {
            background-color: #32382a !important;
            color: white !important;
            border: none !important;
            padding: 8px 16px !important;
            border-radius: 8px !important;
            margin-right: 8px !important;
            font-size: 0.875rem !important;
            transition: background-color 0.2s ease !important;
          }
          
          .dt-button:hover {
            background-color: #525845 !important;
          }
          
          input[type="text"],
          input[type="search"],
          textarea {
            background-color: white;
            color: #25291f;
            border: 1px solid #bcc2a9;
            padding: 8px 12px;
            border-radius: 8px;
            outline: none;
            transition: border-color 0.2s ease;
          }
          
          input:focus,
          textarea:focus {
            border-color: #636b54;
          }
          
          button {
            background-color: #32382a;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.2s ease;
            font-weight: 500;
          }
          
          button:hover {
            background-color: #525845;
          }
          
          pre {
            background-color: #f5f6f3;
            border: 1px solid #d8dbc7;
            border-radius: 8px;
            padding: 16px;
            overflow-x: auto;
          }
          
          a {
            color: #636b54;
            text-decoration: none;
            transition: color 0.2s ease;
          }
          
          a:hover {
            color: #525845;
            text-decoration: underline;
          }
          
          .progress-bar {
            height: 32px;
            background-color: #f5f6f3;
            border-radius: 9999px;
            overflow: hidden;
            display: flex;
          }
          
          .progress-segment {
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 500;
            font-size: 0.875rem;
            transition: width 0.3s ease;
          }
          
          .progress-success {
            background-color: #979f83;
          }
          
          .progress-danger {
            background-color: #ef4444;
          }
          
          .highlight-keyword {
            color: #ef4444;
            font-weight: 600;
          }
          
          .collapsible-header {
            cursor: pointer;
            user-select: none;
          }
          
          .collapsible-header:hover {
            background-color: #f5f6f3;
          }
          
          .chevron {
            transition: transform 0.2s ease;
          }
          
          .chevron.collapsed {
            transform: rotate(-90deg);
          }
          
          @keyframes fadeIn {
            from {
              opacity: 0;
              transform: translateY(10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }
          
          .fade-in {
            animation: fadeIn 0.3s ease;
          }

          
          .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
          }
          
          .badge-success {
            background-color: #979f83;
            color: white;
          }
          
          .badge-danger {
            background-color: #ef4444;
            color: white;
          }
          
          .badge-warning {
            background-color: #f59e0b;
            color: white;
          }
          
          table.dataTable {
            border-collapse: separate;
            border-spacing: 0;
            border: 1px solid #d8dbc7;
            border-radius: 12px;
            overflow: hidden;
          }
          
          table.dataTable thead th {
            background-color: #32382a;
            color: white;
            font-weight: 500;
            border: none;
            padding: 12px 16px;
          }
          
          table.dataTable tbody td {
            border-top: 1px solid #d8dbc7;
            padding: 12px 16px;
          }
          
          table.dataTable tbody tr:hover {
            background-color: #f5f6f3;
          }
          
          .dt-buttons {
            margin-bottom: 16px;
          }
          
          .dt-button {
            background-color: #32382a !important;
            color: white !important;
            border: none !important;
            padding: 8px 16px !important;
            border-radius: 8px !important;
            margin-right: 8px !important;
            font-size: 0.875rem !important;
            transition: background-color 0.2s ease !important;
          }
          
          .dt-button:hover {
            background-color: #525845 !important;
          }
          
          input[type="text"],
          input[type="search"],
          textarea {
            background-color: white;
            color: #25291f;
            border: 1px solid #bcc2a9;
            padding: 8px 12px;
            border-radius: 8px;
            outline: none;
            transition: border-color 0.2s ease;
          }
          
          input:focus,
          textarea:focus {
            border-color: #636b54;
          }
          
          button {
            background-color: #32382a;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.2s ease;
            font-weight: 500;
          }
          
          button:hover {
            background-color: #525845;
          }
          
          pre {
            background-color: #f5f6f3;
            border: 1px solid #d8dbc7;
            border-radius: 8px;
            padding: 16px;
            overflow-x: auto;
          }
          
          a {
            color: #636b54;
            text-decoration: none;
            transition: color 0.2s ease;
          }
          
          a:hover {
            color: #525845;
            text-decoration: underline;
          }
          
          .progress-bar {
            height: 32px;
            background-color: #f5f6f3;
            border-radius: 9999px;
            overflow: hidden;
            display: flex;
          }
          
          .progress-segment {
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 500;
            font-size: 0.875rem;
            transition: width 0.3s ease;
          }
          
          .progress-success {
            background-color: #979f83;
          }
          
          .progress-danger {
            background-color: #ef4444;
          }
          
          .highlight-keyword {
            color: #ef4444;
            font-weight: 600;
          }
          
          .collapsible-header {
            cursor: pointer;
            user-select: none;
          }
          
          .collapsible-header:hover {
            background-color: #f5f6f3;
          }
          
          .chevron {
            transition: transform 0.2s ease;
          }
          
          .chevron.collapsed {
            transform: rotate(-90deg);
          }
          
          @keyframes fadeIn {
            from {
              opacity: 0;
              transform: translateY(10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }
          
          .fade-in {
            animation: fadeIn 0.3s ease;
          }

          /* ===== PDF-OPTIMIZED STYLES ===== */
          /* Higher density layout for print/PDF output */

          @media print, screen {
            body {
              font-size: 10pt;
              line-height: 1.3;
            }

            h1 {
              font-size: 18pt;
              margin: 8pt 0 6pt 0;
            }

            h2 {
              font-size: 14pt;
              margin: 6pt 0 4pt 0;
            }

            h3 {
              font-size: 11pt;
              margin: 4pt 0 3pt 0;
            }

            table.dataTable thead th {
              padding: 4pt 6pt;
              font-size: 9pt;
            }

            table.dataTable tbody td {
              padding: 3pt 6pt;
              font-size: 9pt;
            }

            .badge {
              padding: 2pt 8pt;
              font-size: 8pt;
            }

            pre {
              padding: 8pt;
              font-size: 8pt;
            }

            .card {
              margin-bottom: 8pt;
            }
          }

          @media print {
            @page {
              size: letter;
              margin: 0.5in;
            }

            body {
              margin: 0;
              padding: 0;
            }

            /* Hide interactive elements */
            .dt-buttons,
            button,
            .no-print,
            nav {
              display: none !important;
            }

            /* Page break control */
            h1, h2, h3 {
              page-break-after: avoid;
            }

            table {
              page-break-inside: avoid;
            }

            tr {
              page-break-inside: avoid;
            }

            #webservices h2,
            #onlinehosts h2,
            #onlinehosts h4 {
              page-break-after: avoid;
              break-after: avoid;
            }

            #web-services {
              width: 100% !important;
              table-layout: fixed !important;
            }

            #web-services th,
            #web-services td {
              width: auto;
              padding: 2pt !important;
              font-size: 7pt !important;
              vertical-align: top;
              word-break: break-word;
              overflow-wrap: anywhere;
            }

            #web-services th:nth-child(1),
            #web-services td:nth-child(1) { width: 12%; }
            #web-services th:nth-child(2),
            #web-services td:nth-child(2) { width: 13%; }
            #web-services th:nth-child(3),
            #web-services td:nth-child(3) { width: 5%; }
            #web-services th:nth-child(4),
            #web-services td:nth-child(4) { width: 8%; }
            #web-services th:nth-child(5),
            #web-services td:nth-child(5) { width: 15%; }
            #web-services th:nth-child(6),
            #web-services td:nth-child(6) { width: 8%; }
            #web-services th:nth-child(7),
            #web-services td:nth-child(7) { width: 12%; }
            #web-services th:nth-child(8),
            #web-services td:nth-child(8) { width: 11%; }
            #web-services th:nth-child(9),
            #web-services td:nth-child(9) { width: 16%; }

            #onlinehosts .card {
              page-break-inside: avoid;
              break-inside: avoid;
            }

            #onlinehosts .collapsible-header {
              page-break-after: avoid;
              break-after: avoid;
            }

            /* Remove hover effects */
            .card:hover {
              border-color: #d8dbc7;
              box-shadow: none;
            }

            table.dataTable tbody tr:hover {
              background-color: transparent;
            }
          }
        </style>
        
        <title>Nmap Scan Results</title>
      </head>
      
      <body class="min-h-screen">
        <!-- Fixed Navigation -->
        <nav class="fixed top-0 left-0 right-0 bg-white border-b border-olive-200 z-50 shadow-sm">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
              <div class="flex items-center space-x-8">
                <span class="text-2xl font-display font-semibold text-olive-900">Nmap Results</span>
                <div class="hidden md:flex space-x-6">
                  <a href="#scannedhosts" class="nav-link text-sm font-medium text-olive-700">Scanned Hosts</a>
                  <a href="#openservices" class="nav-link text-sm font-medium text-olive-700">Open Services</a>
                  <a href="#webservices" class="nav-link text-sm font-medium text-olive-700">Web Services</a>
                  <a href="#productversions" class="nav-link text-sm font-medium text-olive-700">Product Versions</a>
                  <xsl:if test="count(/nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']) &gt; 0">
                    <a href="#ssh-auth" class="nav-link text-sm font-medium text-olive-700">SSH Auth</a>
                  </xsl:if>
                  <a href="#onlinehosts" class="nav-link text-sm font-medium text-olive-700">Online Hosts</a>
                </div>
              </div>
              <div class="flex items-center space-x-4">
                <a href="https://www.pentestfactory.de/schwachstellendatenbank/" target="_blank" 
                   class="text-sm text-olive-600 hover:text-olive-800" title="Vulnerability Database">CVEs ↗</a>
                <a href="https://www.ssllabs.com/ssltest/" target="_blank" 
                   class="text-sm text-olive-600 hover:text-olive-800" title="SSL Server Test">SSL/TLS ↗</a>
                <a href="https://securityheaders.com/" target="_blank" 
                   class="text-sm text-olive-600 hover:text-olive-800" title="HTTP Header Test">Headers ↗</a>
              </div>
            </div>
          </div>
        </nav>

        <!-- Main Content -->
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-12">
          
          <!-- Hero Section -->
          <div class="card p-8 mb-8 fade-in">
            <h1 class="text-4xl font-display font-bold text-olive-900 mb-2">Nmap Port Scanning Results</h1>
            <p class="text-olive-600 mb-4">
              Version <xsl:value-of select="/nmaprun/@version"/> · 
              <xsl:value-of select="/nmaprun/@startstr"/> – <xsl:value-of select="/nmaprun/runstats/finished/@timestr"/>
            </p>
            
            <div class="bg-olive-50 border border-olive-200 rounded-lg p-4 mb-6">
              <pre class="text-xs overflow-x-auto"><a target="_blank" class="text-olive-700 hover:text-olive-900"><xsl:attribute name="href">https://explainshell.com/explain?cmd=<xsl:value-of select="/nmaprun/@args"/></xsl:attribute><xsl:value-of select="/nmaprun/@args"/></a></pre>
            </div>
            
            <div class="grid grid-cols-3 gap-4 mb-6">
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-900"><xsl:value-of select="/nmaprun/runstats/hosts/@total"/></div>
                <div class="text-sm text-olive-600">Total Hosts</div>
              </div>
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-600"><xsl:value-of select="/nmaprun/runstats/hosts/@up"/></div>
                <div class="text-sm text-olive-600">Hosts Up</div>
              </div>
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-400"><xsl:value-of select="/nmaprun/runstats/hosts/@down"/></div>
                <div class="text-sm text-olive-600">Hosts Down</div>
              </div>
            </div>
            
            <div class="progress-bar mb-6" aria-hidden="true">
              <div class="progress-segment progress-success">
                <xsl:attribute name="style">width:<xsl:value-of select="/nmaprun/runstats/hosts/@up div /nmaprun/runstats/hosts/@total * 100"/>%;</xsl:attribute>
              </div>
              <div class="progress-segment progress-danger">
                <xsl:attribute name="style">width:<xsl:value-of select="/nmaprun/runstats/hosts/@down div /nmaprun/runstats/hosts/@total * 100"/>%;</xsl:attribute>
              </div>
            </div>
            

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6 pdf-card-grid-3">
              <!-- Network Range -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Network Scanned</h3>
                <div class="space-y-1">
                  <div class="text-sm text-olive-700">
                    <span class="font-medium">Target:</span>
                    <xsl:text>&#160;</xsl:text>
                    <xsl:call-template name="last-command-argument">
                      <xsl:with-param name="arguments" select="/nmaprun/@args"/>
                    </xsl:call-template>
                  </div>
                  <div class="text-sm text-olive-700">
                    <span class="font-medium">IPs:</span><xsl:text>&#160;</xsl:text><xsl:value-of select="/nmaprun/runstats/hosts/@total"/>
                  </div>
                  <div class="text-sm text-olive-700">
                    <span class="font-medium">Started:</span><xsl:text>&#160;</xsl:text><xsl:value-of select="/nmaprun/@startstr"/>
                  </div>
                  <div class="text-sm text-olive-700">
                    <span class="font-medium">Duration:</span>
                    <xsl:text>&#160;</xsl:text><xsl:value-of select="/nmaprun/runstats/finished/@elapsed"/>s
                  </div>
                </div>
              </div>

              <!-- Vulnerability Severity -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Vulnerability Levels</h3>
                <p class="mb-3 text-xs text-olive-600">CVE matches depend on identified service versions and the external Vulners lookup. No findings do not prove a host is free of vulnerabilities.</p>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-red-600 font-medium">Critical (CVSS ≥9.0)</span>
                    <span id="vuln-critical-count" class="text-sm font-bold text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &gt;= 9])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-orange-600 font-medium">High (CVSS ≥7.0)</span>
                    <span id="vuln-high-count" class="text-sm font-bold text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &gt;= 7 and number(.) &lt; 9])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-yellow-600 font-medium">Medium (CVSS ≥4.0)</span>
                    <span id="vuln-medium-count" class="text-sm font-bold text-yellow-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &gt;= 4 and number(.) &lt; 7])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-green-600 font-medium">Low (CVSS &lt;4.0)</span>
                    <span id="vuln-low-count" class="text-sm font-bold text-green-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &lt; 4])"/>
                    </span>
                  </div>
                </div>
              </div>
              </div>



            <!-- CVE Findings Summary (#167 v2) -->
            <xsl:if test="//script[@id='vulners']">
              <div class="border-t border-olive-200 pt-6 mb-6">
                <h3 class="text-lg font-display font-semibold text-olive-900 mb-3">CVE Findings</h3>
                <table class="w-full text-left border border-olive-200 rounded">
                  <thead>
                    <tr class="bg-olive-50">
                      <th class="px-3 py-2 text-xs font-bold uppercase tracking-wide text-olive-700">CVE ID</th>
                      <th class="px-3 py-2 text-xs font-bold uppercase tracking-wide text-olive-700">Port / CPE Host</th>
                      <th class="px-3 py-2 text-xs font-bold uppercase tracking-wide text-olive-700">Reference</th>
                    </tr>
                  </thead>
                  <tbody>
                    <xsl:for-each select="/nmaprun/host">
                      <xsl:variable name="host-ip" select="address/@addr"/>
                      <xsl:for-each select=".//script[@id='vulners']">
                        <xsl:call-template name="vulners-lines">
                          <xsl:with-param name="text" select="@output"/>
                          <xsl:with-param name="port" select="$host-ip"/>
                        </xsl:call-template>
                      </xsl:for-each>
                    </xsl:for-each>
                  </tbody>
                </table>
              </div>
            </xsl:if>

            <!-- Keyword Highlighting -->
            <div class="border-t border-olive-200 pt-6">
              <label class="block text-sm font-medium text-olive-900 mb-2">Highlight Keywords in Services</label>
              <textarea id="keyword-input" rows="2" placeholder="sha1, password, md5, login..." 
                        class="w-full mb-3">sha1,login,password,md5</textarea>
              <div class="flex space-x-3 no-print">
                <button id="highlight-button" type="button" data-report-action="highlight">Apply Highlighting</button>
                <button type="button" data-report-action="reset" class="bg-olive-400">Reset</button>
              </div>
            </div>
          </div>

          <!-- Scanned Hosts -->
          <div id="scannedhosts" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">
              Scanned Hosts
              <xsl:if test="/nmaprun/runstats/hosts/@down > 1024">
                <span class="text-lg text-olive-600 font-normal"> (offline hosts hidden)</span>
              </xsl:if>
            </h2>
            <div class="card p-6">
              <table id="table-overview" class="w-full">
                <thead>
                  <tr>
                    <th class="text-left">State</th>
                    <th class="text-left">Address</th>
                    <th class="text-left">Hostname</th>
                    <th class="text-left">TCP (open)</th>
                    <th class="text-left">UDP (open)</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:choose>
                    <xsl:when test="/nmaprun/runstats/hosts/@down > 1024">
                      <xsl:for-each select="/nmaprun/host[status/@state='up']">
                        <tr>
                          <td>
                            <span class="badge">
                              <xsl:attribute name="class">badge <xsl:choose><xsl:when test="status/@state='up'">badge-success</xsl:when><xsl:otherwise>badge-danger</xsl:otherwise></xsl:choose></xsl:attribute>
                              <xsl:value-of select="status/@state"/>
                            </span>
                          </td>
                          <td>
                            <a class="font-mono text-sm">
                              <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                              <xsl:value-of select="address/@addr"/>
                            </a>
                          </td>
                          <td class="text-olive-700"><xsl:value-of select="hostnames/hostname/@name"/></td>
                          <td class="text-center"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                          <td class="text-center"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                        </tr>
                      </xsl:for-each>
                    </xsl:when>
                    <xsl:otherwise>
                      <xsl:for-each select="/nmaprun/host">
                        <tr>
                          <td>
                            <span class="badge">
                              <xsl:attribute name="class">badge <xsl:choose><xsl:when test="status/@state='up'">badge-success</xsl:when><xsl:otherwise>badge-danger</xsl:otherwise></xsl:choose></xsl:attribute>
                              <xsl:value-of select="status/@state"/>
                            </span>
                          </td>
                          <td>
                            <a class="font-mono text-sm">
                              <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                              <xsl:value-of select="address/@addr"/>
                            </a>
                          </td>
                          <td class="text-olive-700"><xsl:value-of select="hostnames/hostname/@name"/></td>
                          <td class="text-center"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                          <td class="text-center"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                        </tr>
                      </xsl:for-each>
                    </xsl:otherwise>
                  </xsl:choose>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Open Services -->
          <div id="openservices" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Open Services</h2>
            <div class="card p-6">
              <table id="table-services" class="w-full text-sm">
                <thead>
                  <tr>
                    <th class="text-left">Hostname</th>
                    <th class="text-left">Address</th>
                    <th class="text-left">Port</th>
                    <th class="text-left">Protocol</th>
                    <th class="text-left">Service</th>
                    <th class="text-left">Product</th>
                    <th class="text-left">Version</th>
                    <th class="text-left">Extra</th>
                    <th class="text-left">SSL Cert</th>
                    <th class="text-left">Title</th>
                    <th class="text-left">CPE</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="/nmaprun/host">
                    <xsl:for-each select="ports/port[state/@state='open']">
                      <tr>
                        <td class="text-olive-700">
                          <xsl:choose>
                            <xsl:when test="count(../../hostnames/hostname) = 0">N/A</xsl:when>
                            <xsl:otherwise><xsl:value-of select="../../hostnames/hostname/@name"/></xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/></xsl:attribute>
                            <xsl:value-of select="../../address/@addr"/>
                          </a>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute>
                            <xsl:value-of select="@portid"/>
                          </a>
                        </td>
                        <td><xsl:value-of select="@protocol"/></td>
                        <td>
                          <xsl:if test="count(service/@tunnel) > 0">
                            <span class="text-olive-600"><xsl:value-of select="service/@tunnel"/>/</span>
                          </xsl:if>
                          <xsl:value-of select="service/@name"/>
                        </td>
                        <td><xsl:value-of select="service/@product"/></td>
                        <td><xsl:value-of select="service/@version"/></td>
                        <td class="text-olive-600"><xsl:value-of select="service/@extrainfo"/></td>
                        <td class="text-xs">
                          <xsl:if test="count(script/table[@key='subject']/elem[@key='commonName']) > 0">
                            <div><span class="text-olive-600">CN:</span> <xsl:value-of select="script/table[@key='subject']/elem[@key='commonName']"/></div>
                          </xsl:if>
                          <xsl:if test="count(script/table[@key='validity']/elem[@key='notAfter']) > 0">
                            <div><span class="text-olive-600">Expiry:</span> <xsl:value-of select="script/table[@key='validity']/elem[@key='notAfter']"/></div>
                          </xsl:if>
                        </td>
                        <td class="italic text-olive-600">
                          <xsl:choose>
                            <xsl:when test="count(script[@id='http-title']/elem[@key='title']) > 0">
                              <xsl:value-of select="script[@id='http-title']/elem[@key='title']"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:if test="count(script[@id='http-title']/@output) > 0">
                                <xsl:value-of select="script[@id='http-title']/@output"/>
                              </xsl:if>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td class="font-mono text-xs">
                          <xsl:variable name="c22" select="service/cpe"/>
                          <xsl:variable name="afterA" select="substring-after($c22, 'cpe:/a:')"/>
                          <xsl:variable name="vendor" select="substring-before($afterA, ':')"/>
                          <xsl:variable name="afterVendor" select="substring-after($afterA, ':')"/>
                          <xsl:variable name="product" select="substring-before($afterVendor, ':')"/>
                          <xsl:variable name="verRaw" select="substring-after($afterVendor, ':')"/>
                          <xsl:variable name="verNorm" select="substring-before(concat($verRaw,'-'), '-')"/>
                          <xsl:variable name="verFinal" select="normalize-space($verNorm)"/>

                          <xsl:choose>
                            <xsl:when test="string($c22)">
                              <xsl:choose>
                                <xsl:when test="string-length($verFinal) &gt; 0">
                                  <a target="_blank" class="text-olive-700">
                                    <xsl:attribute name="href">https://cve.pentestfactory.de/?cpe=<xsl:value-of select="$c22"/></xsl:attribute>
                                    <xsl:value-of select="$c22"/>
                                  </a>
                                </xsl:when>
                                <xsl:otherwise><xsl:value-of select="$c22"/></xsl:otherwise>
                              </xsl:choose>
                            </xsl:when>
                            <xsl:otherwise><span class="text-olive-400">unknown</span></xsl:otherwise>
                          </xsl:choose>
                        </td>
                      </tr>
                    </xsl:for-each>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Web Services -->
          <div id="webservices" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Web Services</h2>
            <div class="card p-6">
              <table id="web-services" class="w-full text-sm">
                <thead>
                  <tr>
                    <th class="text-left">Hostname</th>
                    <th class="text-left">Address</th>
                    <th class="text-left">Port</th>
                    <th class="text-left">Service</th>
                    <th class="text-left">Product</th>
                    <th class="text-left">Version</th>
                    <th class="text-left">Title</th>
                    <th class="text-left">SSL Cert</th>
                    <th class="text-left">URL</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="/nmaprun/host">
                    <xsl:for-each select="ports/port[starts-with(service/@name, 'http') and state/@state='open' and @protocol='tcp']">
                      <tr>
                        <td class="text-olive-700">
                          <xsl:choose>
                            <xsl:when test="count(../../hostnames/hostname) = 0">N/A</xsl:when>
                            <xsl:otherwise><xsl:value-of select="../../hostnames/hostname/@name"/></xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/></xsl:attribute>
                            <xsl:value-of select="../../address/@addr"/>
                          </a>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute>
                            <xsl:value-of select="@portid"/>
                          </a>
                        </td>
                        <td>
                          <xsl:if test="count(service/@tunnel) > 0">
                            <span class="text-olive-600"><xsl:value-of select="service/@tunnel"/>/</span>
                          </xsl:if>
                          <xsl:value-of select="service/@name"/>
                        </td>
                        <td><xsl:value-of select="service/@product"/></td>
                        <td><xsl:value-of select="service/@version"/></td>
                        <td class="italic text-olive-600">
                          <xsl:choose>
                            <xsl:when test="count(script[@id='http-title']/elem[@key='title']) > 0">
                              <xsl:value-of select="script[@id='http-title']/elem[@key='title']"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:if test="count(script[@id='http-title']/@output) > 0">
                                <xsl:value-of select="script[@id='http-title']/@output"/>
                              </xsl:if>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td class="text-xs">
                          <xsl:if test="count(script/table[@key='subject']/elem[@key='commonName']) > 0">
                            <div><span class="text-olive-600">CN:</span> <xsl:value-of select="script/table[@key='subject']/elem[@key='commonName']"/></div>
                          </xsl:if>
                          <xsl:if test="count(script/table[@key='validity']/elem[@key='notAfter']) > 0">
                            <div><span class="text-olive-600">Expiry:</span> <xsl:value-of select="script/table[@key='validity']/elem[@key='notAfter']"/></div>
                          </xsl:if>
                        </td>
                        <td>
                          <xsl:choose>
                            <xsl:when test="count(service/@tunnel) > 0 or service/@name = 'https' or service/@name = 'https-alt'">
                              <xsl:choose>
                                <xsl:when test="count(../../hostnames/hostname) > 0">
                                  <a target="_blank" class="font-mono text-xs">
                                    <xsl:attribute name="href">https://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/></xsl:attribute>
                                    https://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/>
                                  </a>
                                </xsl:when>
                                <xsl:otherwise>
                                  <a target="_blank" class="font-mono text-xs">
                                    <xsl:attribute name="href">https://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/></xsl:attribute>
                                    https://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/>
                                  </a>
                                </xsl:otherwise>
                              </xsl:choose>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:choose>
                                <xsl:when test="count(../../hostnames/hostname) > 0">
                                  <a target="_blank" class="font-mono text-xs">
                                    <xsl:attribute name="href">http://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/></xsl:attribute>
                                    http://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/>
                                  </a>
                                </xsl:when>
                                <xsl:otherwise>
                                  <a target="_blank" class="font-mono text-xs">
                                    <xsl:attribute name="href">http://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/></xsl:attribute>
                                    http://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/>
                                  </a>
                                </xsl:otherwise>
                              </xsl:choose>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                      </tr>
                    </xsl:for-each>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Product Versions -->
          <div id="productversions" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Product Versions</h2>
            <div class="card p-6">
              <table id="table-product-versions" class="w-full text-sm">
                <thead>
                  <tr>
                    <th class="text-left">Product</th>
                    <th class="text-left">Version</th>
                    <th class="text-left">Count</th>
                    <th class="text-left">Host List</th>
                    <th class="text-left">CPE</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="/nmaprun/host/ports/port[state/@state='open']/service[@product and @version][generate-id() = generate-id(key('svcByProdVer', concat(@product,'|',@version))[1])]">
                    <xsl:sort select="@product"/>
                    <xsl:sort select="@version"/>

                    <xsl:variable name="pv" select="concat(@product,'|',@version)"/>
                    <xsl:variable name="services" select="key('svcByProdVer', $pv)"/>
                    <xsl:variable name="uniqHosts" select="$services[generate-id() = generate-id(key('svcByProdVerHost', concat(@product,'|',@version,'|', ancestor::host/address/@addr))[1])]"/>
                    <xsl:variable name="cpe22" select="$services/cpe[starts-with(., 'cpe:/a:')][1]"/>
                    <xsl:variable name="afterA" select="substring-after($cpe22, 'cpe:/a:')"/>
                    <xsl:variable name="verRaw" select="substring-after(substring-after($afterA, ':'), ':')"/>
                    <xsl:variable name="verNorm" select="substring-before(concat($verRaw,'-'), '-')"/>
                    <xsl:variable name="verFinal" select="normalize-space($verNorm)"/>

                    <tr>
                      <td class="font-medium"><xsl:value-of select="@product"/></td>
                      <td><xsl:value-of select="@version"/></td>
                      <td class="text-center font-medium text-olive-700"><xsl:value-of select="count($uniqHosts)"/></td>
                      <td class="text-xs">
                        <xsl:for-each select="key('svcByProdVer', $pv)[generate-id() = generate-id(key('svcByProdVerHostPort', concat(@product,'|',@version,'|', ancestor::host/address/@addr,'|', ../@protocol,'|',../@portid))[1])]">
                          <xsl:sort select="ancestor::host/hostnames/hostname[1]/@name"/>
                          <xsl:sort select="ancestor::host/address/@addr"/>
                          <xsl:sort select="../@protocol"/>
                          <xsl:sort select="../@portid" data-type="number"/>

                          <xsl:variable name="h" select="ancestor::host"/>
                          <xsl:variable name="ip" select="$h/address/@addr"/>
                          <xsl:variable name="hn" select="$h/hostnames/hostname[1]/@name"/>
                          <xsl:variable name="proto" select="translate(../@protocol, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
                          <xsl:variable name="port" select="../@portid"/>

                          <a class="inline-block mb-1">
                            <xsl:attribute name="href">#port-<xsl:value-of select="translate($ip, '.', '-')"/>-<xsl:value-of select="$port"/></xsl:attribute>
                            <xsl:choose>
                              <xsl:when test="string-length($hn) &gt; 0">
                                <xsl:value-of select="$hn"/> (<xsl:value-of select="$ip"/>)
                              </xsl:when>
                              <xsl:otherwise><xsl:value-of select="$ip"/></xsl:otherwise>
                            </xsl:choose>
                            <span class="text-olive-600"> [<xsl:value-of select="$proto"/>/<xsl:value-of select="$port"/>]</span>
                          </a>
                          <xsl:if test="position() != last()">, </xsl:if>
                        </xsl:for-each>
                      </td>
                      <td class="font-mono text-xs">
                        <xsl:choose>
                          <xsl:when test="string($cpe22)">
                            <xsl:choose>
                              <xsl:when test="string-length($verFinal) &gt; 0">
                                <a target="_blank" class="text-olive-700">
                                  <xsl:attribute name="href">https://cve.pentestfactory.de/?cpe=<xsl:value-of select="$cpe22"/></xsl:attribute>
                                  <xsl:value-of select="$cpe22"/>
                                </a>
                              </xsl:when>
                              <xsl:otherwise><xsl:value-of select="$cpe22"/></xsl:otherwise>
                            </xsl:choose>
                          </xsl:when>
                          <xsl:otherwise><span class="text-olive-400">unknown</span></xsl:otherwise>
                        </xsl:choose>
                      </td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </div>

          <!-- SSH Authentication -->
          <xsl:if test="count(/nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']) &gt; 0">
            <div id="ssh-auth" class="mb-12 fade-in">
              <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">SSH Authentication</h2>
              <div class="card p-6">
                <table id="table-ssh-auth" class="w-full text-sm">
                  <thead>
                    <tr>
                      <th class="text-left">Host</th>
                      <th class="text-left">IP</th>
                      <th class="text-left">Port</th>
                      <th class="text-left">Product</th>
                      <th class="text-left">Version</th>
                      <th class="text-left">Auth Methods</th>
                    </tr>
                  </thead>
                  <tbody>
                    <xsl:for-each select="key('sshSvcs', 1)">
                      <xsl:sort select="ancestor::host/hostnames/hostname[1]/@name"/>
                      <xsl:sort select="ancestor::host/address/@addr"/>
                      <xsl:sort select="../@portid" data-type="number"/>

                      <xsl:variable name="host" select="ancestor::host"/>
                      <xsl:variable name="ip" select="$host/address/@addr"/>
                      <xsl:variable name="hn" select="$host/hostnames/hostname[1]/@name"/>
                      <xsl:variable name="port" select="../@portid"/>
                      <xsl:variable name="proto" select="translate(../@protocol,'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
                      <xsl:variable name="methods" select="../script[@id='ssh-auth-methods']/table[@key='Supported authentication methods']/elem"/>

                      <tr>
                        <td class="text-olive-700">
                          <xsl:choose>
                            <xsl:when test="string-length($hn) &gt; 0"><xsl:value-of select="$hn"/></xsl:when>
                            <xsl:otherwise>-</xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate($ip,'.','-')"/></xsl:attribute>
                            <xsl:value-of select="$ip"/>
                          </a>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#port-<xsl:value-of select="translate($ip,'.','-')"/>-<xsl:value-of select="$port"/></xsl:attribute>
                            <xsl:value-of select="$proto"/>/<xsl:value-of select="$port"/>
                          </a>
                        </td>
                        <td><xsl:value-of select="@product"/></td>
                        <td><xsl:value-of select="@version"/></td>
                        <td>
                          <xsl:choose>
                            <xsl:when test="count($methods) &gt; 0">
                              <xsl:for-each select="$methods">
                                <span class="badge badge-warning mr-1"><xsl:value-of select="."/></span>
                              </xsl:for-each>
                            </xsl:when>
                            <xsl:otherwise>-</xsl:otherwise>
                          </xsl:choose>
                        </td>
                      </tr>
                    </xsl:for-each>
                  </tbody>
                </table>
              </div>
            </div>
          </xsl:if>

          <!-- Online Hosts -->
          <div id="onlinehosts" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Online Hosts</h2>
            
            <xsl:for-each select="/nmaprun/host[status/@state='up']">
              <div class="card mb-6">
                <div class="collapsible-header p-6 border-b border-olive-200">
                  <xsl:attribute name="id">onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                  <xsl:attribute name="role">button</xsl:attribute>
                  <xsl:attribute name="tabindex">0</xsl:attribute>
                  <xsl:attribute name="aria-expanded">true</xsl:attribute>
                  <xsl:attribute name="aria-controls">content-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                  <xsl:attribute name="data-collapse-target">content-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                  <div class="flex items-center justify-between">
                    <div>
                      <h3 class="text-xl font-display font-bold text-olive-900">
                        <span class="chevron inline-block mr-2">▼</span>
                        <xsl:value-of select="address/@addr"/>
                        <xsl:if test="count(hostnames/hostname) > 0">
                          <span class="text-olive-600 font-normal"> – <xsl:value-of select="hostnames/hostname/@name"/></span>
                        </xsl:if>
                      </h3>
                    </div>
                    <span class="badge badge-success">
                      <xsl:value-of select="count(ports/port[state/@state='open'])"/> open ports
                    </span>
                  </div>
                </div>
                
                <div class="p-6">
                  <xsl:attribute name="id">content-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                  
                  <xsl:if test="count(hostnames/hostname) > 0">
                    <div class="mb-6">
                      <h4 class="text-lg font-display font-semibold text-olive-900 mb-3">Hostnames</h4>
                      <ul class="list-disc list-inside space-y-1">
                        <xsl:for-each select="hostnames/hostname">
                          <li class="text-olive-700">
                            <xsl:value-of select="@name"/> 
                            <span class="text-olive-500">(<xsl:value-of select="@type"/>)</span>
                          </li>
                        </xsl:for-each>
                      </ul>
                    </div>
                  </xsl:if>
                  
                  <div class="mb-6">
                    <h4 class="text-lg font-display font-semibold text-olive-900 mb-3">Ports</h4>
                    <div class="overflow-x-auto">
                      <table class="w-full text-sm">
                        <thead>
                          <tr>
                            <th class="text-left">Port</th>
                            <th class="text-left">Protocol</th>
                            <th class="text-left">State/Reason</th>
                            <th class="text-left">Service</th>
                            <th class="text-left">Product</th>
                            <th class="text-left">Version</th>
                            <th class="text-left">Extra Info</th>
                          </tr>
                        </thead>
                        <tbody>
                          <xsl:for-each select="ports/port">
                            <tr>
                              <xsl:attribute name="class">
                                <xsl:choose>
                                  <xsl:when test="state/@state = 'open'">bg-olive-50</xsl:when>
                                  <xsl:when test="state/@state = 'filtered'">bg-yellow-50</xsl:when>
                                  <xsl:otherwise>bg-gray-50</xsl:otherwise>
                                </xsl:choose>
                              </xsl:attribute>
                              <td class="font-mono">
                                <xsl:attribute name="id">port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute>
                                <xsl:value-of select="@portid"/>
                              </td>
                              <td><xsl:value-of select="@protocol"/></td>
                              <td>
                                <div><xsl:value-of select="state/@state"/></div>
                                <div class="text-xs text-olive-600"><xsl:value-of select="state/@reason"/></div>
                              </td>
                              <td>
                                <xsl:if test="count(service/@tunnel) > 0">
                                  <span class="text-olive-600"><xsl:value-of select="service/@tunnel"/>/</span>
                                </xsl:if>
                                <xsl:value-of select="service/@name"/>
                              </td>
                              <td><xsl:value-of select="service/@product"/></td>
                              <td><xsl:value-of select="service/@version"/></td>
                              <td class="text-olive-600"><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                            <xsl:if test="count(service/cpe) > 0 or count(script) > 0">
                              <tr>
                                <xsl:attribute name="class">
                                  <xsl:choose>
                                    <xsl:when test="state/@state = 'open'">bg-olive-50</xsl:when>
                                    <xsl:when test="state/@state = 'filtered'">bg-yellow-50</xsl:when>
                                    <xsl:otherwise>bg-gray-50</xsl:otherwise>
                                  </xsl:choose>
                                </xsl:attribute>
                                <td colspan="7" class="text-xs">
                                  <xsl:if test="count(service/cpe) > 0">
                                    <div class="mb-2">
                                      <a target="_blank" class="font-mono text-olive-700">
                                        <xsl:attribute name="href">https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;cves=on&amp;cpe_version=<xsl:value-of select="service/cpe"/></xsl:attribute>
                                        <xsl:value-of select="service/cpe"/>
                                      </a>
                                    </div>
                                  </xsl:if>
                                  <xsl:for-each select="script">
                                    <div class="mb-3">
                                      <h5 class="font-semibold text-olive-800 mb-1"><xsl:value-of select="@id"/></h5>
                                      <xsl:choose>
                                        <xsl:when test="@id = 'vulners'">
                                          <p class="text-xs text-olive-600 italic">CVE details for this service are listed in the CVE Findings table (page 1).</p>
                                        </xsl:when>
                                        <xsl:otherwise>
                                          <pre class="text-xs bg-white p-3 rounded border border-olive-200 overflow-x-auto"><xsl:value-of select="@output"/></pre>
                                        </xsl:otherwise>
                                      </xsl:choose>
                                    </div>
                                  </xsl:for-each>
                                </td>
                              </tr>
                            </xsl:if>
                          </xsl:for-each>
                        </tbody>
                      </table>
                    </div>
                  </div>
                  
                  <xsl:if test="count(hostscript/script) > 0">
                    <div class="mb-6">
                      <h4 class="text-lg font-display font-semibold text-olive-900 mb-3">Host Scripts</h4>
                      <xsl:for-each select="hostscript/script">
                        <div class="mb-3">
                          <h5 class="font-semibold text-olive-800 mb-1"><xsl:value-of select="@id"/></h5>
                          <pre class="text-xs bg-white p-3 rounded border border-olive-200 overflow-x-auto"><xsl:value-of select="@output"/></pre>
                        </div>
                      </xsl:for-each>
                    </div>
                  </xsl:if>
                  
                  <xsl:if test="count(os/osmatch) > 0">
                    <div>
                      <h4 class="text-lg font-display font-semibold text-olive-900 mb-3">OS Detection</h4>
                      <xsl:for-each select="os/osmatch">
                        <div class="mb-4 p-4 bg-olive-50 rounded-lg border border-olive-200">
                          <h5 class="font-semibold text-olive-900 mb-2">
                            <xsl:value-of select="@name"/> 
                            <span class="text-olive-600">(<xsl:value-of select="@accuracy"/>% accuracy)</span>
                          </h5>
                          <xsl:for-each select="osclass">
                            <div class="text-sm text-olive-700 space-y-1">
                              <div><span class="font-medium">Device type:</span> <xsl:value-of select="@type"/></div>
                              <div><span class="font-medium">Running:</span> <xsl:value-of select="@vendor"/> <xsl:value-of select="@osfamily"/> <xsl:value-of select="@osgen"/> (<xsl:value-of select="@accuracy"/>%)</div>
                              <div>
                                <span class="font-medium">OS CPE:</span> 
                                <a target="_blank" class="font-mono text-xs text-olive-700">
                                  <xsl:attribute name="href">https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;cves=on&amp;cpe_version=<xsl:value-of select="cpe"/></xsl:attribute>
                                  <xsl:value-of select="cpe"/>
                                </a>
                              </div>
                            </div>
                          </xsl:for-each>
                        </div>
                      </xsl:for-each>
                    </div>
                  </xsl:if>
                </div>
              </div>
            </xsl:for-each>
          </div>
        </div>

        <!-- Footer -->
        <footer class="bg-white border-t border-olive-200 py-12 mt-12">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-sm text-olive-600">
            <p class="mb-2">
              Report generated by <a href="https://pentestfactory.com" class="text-olive-700 hover:text-olive-900">Pentest Factory GmbH</a>
            </p>
            <p class="mb-4">
              Questions or problems? <a href="mailto:team@pentestfactory.de" class="text-olive-700 hover:text-olive-900">Contact us</a>
            </p>
            <p class="text-xs">
              ❤️ Original Bootstrap template by <a href="https://github.com/honze-net/nmap-bootstrap-xsl" target="_blank" class="text-olive-700">Andreas Hontzia</a> · 
              Tweaks by <a href="https://github.com/l4rm4nd" target="_blank" class="text-olive-700">LRVT</a> · 
              Modern design update 2026
            </p>
          </div>
        </footer>

        <script id="nmapui-report-runtime">__NMAPUI_REPORT_RUNTIME__</script>
      </body>
    </html>
  </xsl:template>

  <xsl:template name="vulners-lines">
    <xsl:param name="text"/>
    <xsl:param name="port"/>
    <xsl:if test="contains($text, 'CVE-')">
      <xsl:variable name="after" select="substring-after($text, 'CVE-')"/>
      <xsl:variable name="rest-tab">
        <xsl:choose>
          <xsl:when test="contains($after, '&#9;')"><xsl:value-of select="substring-before($after, '&#9;')"/></xsl:when>
          <xsl:otherwise><xsl:value-of select="substring-before(concat($after, ' '), ' ')"/></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="cve-id" select="concat('CVE-', normalize-space($rest-tab))"/>
      <tr>
        <td class="px-3 py-1 font-mono text-xs">
          <a target="_blank" class="text-olive-700 hover:underline">
            <xsl:attribute name="href">https://vulners.com/cve/<xsl:value-of select="$cve-id"/></xsl:attribute>
            <xsl:value-of select="$cve-id"/>
          </a>
        </td>
        <td class="px-3 py-1 font-mono text-xs"><xsl:value-of select="$port"/></td>
        <td class="px-3 py-1 text-xs"></td>
      </tr>
      <xsl:call-template name="vulners-lines">
        <xsl:with-param name="text" select="substring-after($after, $cve-id)"/>
        <xsl:with-param name="port" select="$port"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

</xsl:stylesheet>
