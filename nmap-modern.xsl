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

  <xsl:param name="techmore_version"/>
  <xsl:param name="customer_name"/>
  <xsl:param name="report_identifier"/>
  <xsl:param name="report_timestamp"/>
  <xsl:param name="report_display_timestamp"/>
  <xsl:param name="public_ip"/>
  <xsl:param name="local_ip"/>
  <xsl:param name="subnet_mask"/>
  <xsl:param name="cidr"/>
  <xsl:param name="traceroute_summary"/>

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

	          .report-shell {
	            width: min(100% - 32px, 1800px);
	            margin-left: auto;
	            margin-right: auto;
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
	            width: 100% !important;
	          }
	          
	          table.dataTable thead th {
	            background-color: #32382a;
	            color: white;
	            font-weight: 500;
	            border: none;
	            padding: 10px 12px;
	            white-space: nowrap;
	          }
	          
	          table.dataTable tbody td {
	            border-top: 1px solid #d8dbc7;
	            padding: 10px 12px;
	            vertical-align: top;
	          }

	          .table-wide {
	            width: 100% !important;
	            min-width: 1180px;
	          }

	          #table-services,
	          #web-services {
	            min-width: 1680px;
	          }

	          #table-product-versions {
	            min-width: 1420px;
	          }

	          #table-ssh-auth {
	            min-width: 1180px;
	          }

	          .table-scroll {
	            width: 100%;
	            overflow-x: auto;
	            padding-bottom: 4px;
	          }

	          .cell-wrap {
	            white-space: normal;
	            overflow-wrap: anywhere;
	            word-break: break-word;
	          }

	          .cell-nowrap {
	            white-space: nowrap;
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

	          .pdf-cover {
	            display: none;
	          }

	          .pdf-only {
	            display: none;
	          }

          .end-of-report-page {
            display: none;
          }

          .report-network-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 16px;
          }

          .report-network-grid div,
          .report-traceroute-summary {
            background: #f5f6f3;
            border: 1px solid #d8dbc7;
            border-radius: 10px;
            padding: 12px;
          }

          .report-network-grid span,
          .report-traceroute-summary span {
            display: block;
            font-size: 0.7rem;
            color: #636b54;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 4px;
          }

          .report-network-grid strong,
          .report-traceroute-summary strong {
            display: block;
            color: #25291f;
            font-size: 0.9rem;
            overflow-wrap: anywhere;
          }

          .pdf-fixed-header,
          .pdf-fixed-footer {
            display: none;
          }

	          @media print {
	            html {
	              font-size: 7px !important;
	            }

	            body {
	              background-color: #e9ebe0 !important;
	              color: #25291f !important;
	              font-size: 7px !important;
	              line-height: 1.15 !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
	            }

            nav {
              display: none !important;
            }

	            .pdf-cover {
	              display: flex !important;
	              box-sizing: border-box !important;
	              width: 100% !important;
	              height: 279.4mm !important;
	              min-height: 279.4mm !important;
	              page-break-after: always !important;
	              break-after: page !important;
	              background: #414637 !important;
	              color: #f5f6f3 !important;
	              border: 1px solid #636b54 !important;
	              margin: 0 !important;
	              padding: 16mm !important;
	              flex-direction: column !important;
	              justify-content: space-between !important;
	              position: relative !important;
	              z-index: 5 !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
	            }

            .pdf-fixed-header {
              display: flex !important;
              position: fixed !important;
              top: 0 !important;
              left: 0 !important;
              right: 0 !important;
              z-index: 1 !important;
              height: 12mm !important;
              align-items: center !important;
              justify-content: space-between !important;
              color: #f5f6f3 !important;
              font-size: 8px !important;
              font-weight: 700 !important;
              padding: 0 4mm !important;
              background: #414637 !important;
              border-bottom: 1px solid #636b54 !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            .pdf-fixed-header a {
              color: #d8dbc7 !important;
              text-decoration: none !important;
              font-weight: 500 !important;
            }

            .pdf-fixed-footer {
              display: block !important;
              position: fixed !important;
              right: 2mm !important;
              bottom: 1.5mm !important;
              z-index: 1 !important;
              color: #636b54 !important;
              font-size: 7px !important;
            }

            .pdf-fixed-footer::after {
              content: "Page " counter(page);
            }

	            .pdf-cover * {
	              color: inherit !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
	            }

	            .pdf-cover-label {
	              font-size: 10px !important;
	              letter-spacing: 0.14em !important;
	              text-transform: uppercase !important;
	              color: #d8dbc7 !important;
	            }

	            .pdf-cover-title {
	              font-size: 38px !important;
	              line-height: 0.95 !important;
	              font-weight: 700 !important;
	              margin-top: 8mm !important;
	              margin-bottom: 4mm !important;
	            }

	            .pdf-cover-subtitle {
	              font-size: 16px !important;
	              line-height: 1.1 !important;
	              color: #e9ebe0 !important;
	            }

	            .pdf-cover-meta {
	              display: grid !important;
	              grid-template-columns: repeat(4, minmax(0, 1fr)) !important;
	              gap: 3mm !important;
	              border-top: 1px solid #979f83 !important;
	              padding-top: 5mm !important;
            }

	            .pdf-cover-meta div {
	              background: rgba(245,246,243,0.08) !important;
	              border: 1px solid rgba(216,219,199,0.35) !important;
	              padding: 3.5mm !important;
	            }

	            .pdf-cover-meta span {
	              display: block !important;
	              font-size: 7px !important;
	              color: #d8dbc7 !important;
	              text-transform: uppercase !important;
	              letter-spacing: 0.08em !important;
            }

	            .pdf-cover-meta strong {
	              display: block !important;
	              font-size: 10px !important;
	              line-height: 1.15 !important;
	              margin-top: 2mm !important;
	              word-break: break-word !important;
            }

	            .pdf-summary-title {
	              display: block !important;
	              font-size: 13px !important;
	              line-height: 1.1 !important;
	              margin-bottom: 3px !important;
            }

	            .pdf-summary-subtitle {
	              display: block !important;
	              font-size: 8px !important;
	              line-height: 1.2 !important;
	              margin-bottom: 3px !important;
            }

	            .pdf-only {
	              display: block !important;
	            }

            .end-of-report-page {
              display: flex !important;
              box-sizing: border-box !important;
              width: 100% !important;
              height: 279.4mm !important;
              min-height: 279.4mm !important;
              margin: 0 !important;
              break-before: page !important;
              page-break-before: always !important;
              align-items: center !important;
              justify-content: center !important;
              background: #e9ebe0 !important;
              color: #414637 !important;
              font-size: 24px !important;
              font-weight: 700 !important;
              letter-spacing: 0.14em !important;
              text-transform: uppercase !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

	            .pdf-section-label {
	              font-size: 7px !important;
	              color: #636b54 !important;
	              text-transform: uppercase !important;
	              letter-spacing: 0.12em !important;
	              margin-bottom: 2px !important;
            }

	            .max-w-7xl,
	            .report-shell {
	              max-width: none !important;
	              width: 100% !important;
	              margin-left: 0 !important;
	              margin-right: 0 !important;
	              padding-left: 0 !important;
	              padding-right: 0 !important;
	            }

	            h1 {
	              font-size: 14px !important;
	              line-height: 1.05 !important;
	              margin-bottom: 2px !important;
	            }

	            h2 {
	              font-size: 11px !important;
	              line-height: 1.1 !important;
	              margin-bottom: 3px !important;
	            }

	            h3,
	            h4,
	            h5 {
	              font-size: 8px !important;
	              line-height: 1.1 !important;
	              margin-bottom: 2px !important;
	            }

	            body,
            .card,
            .progress-bar,
            pre,
            table,
            th,
            td {
              box-shadow: none !important;
            }

	            .card {
	              background: rgba(255,255,255,0.88) !important;
	              border: 1px solid #d8dbc7 !important;
	              border-radius: 3px !important;
	              margin-bottom: 1.5mm !important;
	              padding: 3px !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
	            }

	            .p-8,
	            .p-6,
	            .p-5,
	            .p-4 {
	              padding: 3px !important;
	            }

	            .mb-12,
	            .mb-8,
	            .mb-6,
	            .mb-4,
	            .mb-3 {
	              margin-bottom: 2px !important;
	            }

	            .pt-24,
	            .pb-12 {
	              padding-top: 0 !important;
	              padding-bottom: 0 !important;
	            }

            .report-shell.pt-24 {
              padding-top: 15mm !important;
              padding-left: 4mm !important;
              padding-right: 4mm !important;
            }

	            .gap-6,
	            .gap-4,
	            .gap-3 {
	              gap: 2px !important;
	            }

	            .text-4xl,
	            .text-3xl,
	            .text-2xl,
	            .text-xl,
	            .text-lg,
	            .text-sm,
	            .text-xs {
	              font-size: 7px !important;
	              line-height: 1.15 !important;
	            }

	            .badge {
	              padding: 0 2px !important;
	              border-radius: 2px !important;
	              font-size: 6px !important;
	              line-height: 1.1 !important;
	            }

	            table.dataTable thead th {
	              background-color: #32382a !important;
	              color: white !important;
	              padding: 1px 2px !important;
	              font-size: 6px !important;
	              line-height: 1.1 !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
	            }

	            table.dataTable tbody td,
	            table.dataTable tbody th {
	              padding: 1px 2px !important;
	              font-size: 6px !important;
	              line-height: 1.1 !important;
	            }

            .badge-success {
              background-color: #979f83 !important;
              color: white !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            .badge-danger {
              background-color: #ef4444 !important;
              color: white !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            .badge-warning {
              background-color: #f59e0b !important;
              color: white !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            .progress-success {
              background-color: #979f83 !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

	            .progress-danger {
	              background-color: #ef4444 !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
	            }

	            .progress-bar {
	              height: 8px !important;
	            }

	            .progress-segment {
	              font-size: 6px !important;
	              line-height: 1 !important;
	            }

            .dt-buttons,
            .dataTables_paginate,
            .dataTables_length,
            .dataTables_filter,
            .dataTables_info,
            .no-print,
            button,
            input,
            textarea {
              display: none !important;
            }

	            .collapsible-header {
	              display: block !important;
	              background-color: #f5f6f3 !important;
	              padding: 3px !important;
	              page-break-after: avoid !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
            }

            .max-h-64,
            .overflow-y-auto,
            .overflow-x-auto {
              max-height: none !important;
              overflow: visible !important;
            }

            [id^="content-"] {
              display: block !important;
            }

	            pre {
	              background-color: #f5f6f3 !important;
	              border-radius: 2px !important;
	              padding: 2px !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
	              white-space: pre-wrap !important;
	              word-break: break-word !important;
	              font-size: 5px !important;
	              line-height: 1.05 !important;
	            }

            table {
              width: 100% !important;
              page-break-inside: auto !important;
            }

            tr {
              page-break-inside: avoid !important;
              page-break-after: auto !important;
            }

            #scannedhosts,
            #openservices,
            #webservices,
            #productversions,
            #ssh-auth,
            #onlinehosts {
              page-break-after: auto !important;
            }

            .card {
              page-break-inside: auto !important;
            }

	            .pdf-kpi-grid,
	            .pdf-card-grid-4 {
	              display: grid !important;
	              grid-template-columns: repeat(4, minmax(0, 1fr)) !important;
	            }

	            .pdf-card-grid-3 {
	              display: grid !important;
	              grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
	            }

	            .pdf-card-grid-2 {
	              display: grid !important;
	              grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
	            }

	            .pdf-page-two {
	              box-sizing: border-box !important;
	              min-height: 273mm !important;
	              background: #e9ebe0 !important;
	              border-color: #bcc2a9 !important;
	              page-break-after: auto !important;
	              break-after: auto !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
            }

	            .pdf-page-two .card {
	              background: #f5f6f3 !important;
	              border-color: #bcc2a9 !important;
            }

	            .report-network-grid {
	              display: grid !important;
	              grid-template-columns: repeat(4, minmax(0, 1fr)) !important;
	              gap: 2px !important;
	              margin-bottom: 2px !important;
            }

	            .report-network-grid div,
	            .report-traceroute-summary {
	              background: #f5f6f3 !important;
	              border: 1px solid #bcc2a9 !important;
	              border-radius: 3px !important;
	              padding: 3px !important;
	              -webkit-print-color-adjust: exact !important;
	              print-color-adjust: exact !important;
            }

	            .flex-shrink-0 {
	              display: none !important;
	            }

	            @page {
	              size: Letter portrait;
	              margin: 0;
	            }
          }
        </style>

        <title>Nmap Scan Results</title>
      </head>
      
      <body class="min-h-screen">
        <section class="pdf-cover">
          <div>
            <div class="pdf-cover-label">TM-NmapUI</div>
            <div class="pdf-cover-title">Vulnerability Scanning</div>
            <div class="pdf-cover-subtitle">Network Exposure and Service Discovery Report</div>
          </div>
          <div class="pdf-cover-meta">
            <div>
              <span>Customer</span>
              <strong>
                <xsl:choose>
                  <xsl:when test="string-length(normalize-space($customer_name)) &gt; 0">
                    <xsl:value-of select="$customer_name"/>
                  </xsl:when>
                  <xsl:otherwise>Customer Profile</xsl:otherwise>
                </xsl:choose>
              </strong>
            </div>
            <div>
              <span>Report ID</span>
              <strong>
                <xsl:choose>
                  <xsl:when test="string-length(normalize-space($report_identifier)) &gt; 0">
                    <xsl:value-of select="$report_identifier"/>
                  </xsl:when>
                  <xsl:otherwise><xsl:value-of select="/nmaprun/@startstr"/></xsl:otherwise>
                </xsl:choose>
              </strong>
            </div>
            <div>
              <span>Timestamp</span>
              <strong>
                <xsl:choose>
                  <xsl:when test="string-length(normalize-space($report_display_timestamp)) &gt; 0">
                    <xsl:value-of select="$report_display_timestamp"/>
                  </xsl:when>
                  <xsl:when test="string-length(normalize-space($report_timestamp)) &gt; 0">
                    <xsl:value-of select="$report_timestamp"/>
                  </xsl:when>
                  <xsl:otherwise><xsl:value-of select="/nmaprun/runstats/finished/@timestr"/></xsl:otherwise>
                </xsl:choose>
              </strong>
            </div>
            <div>
              <span>Scope</span>
              <strong><xsl:value-of select="/nmaprun/runstats/hosts/@total"/> IPs / <xsl:value-of select="/nmaprun/runstats/hosts/@up"/> online</strong>
            </div>
          </div>
        </section>

        <div class="pdf-fixed-header">
          <span>TM-NmapUI <xsl:value-of select="$techmore_version"/></span>
          <a href="https://techmore.github.io/TM-NMapUI-www">https://techmore.github.io/TM-NMapUI-www</a>
        </div>
        <div class="pdf-fixed-footer"></div>

        <!-- Fixed Navigation -->
        <nav class="fixed top-0 left-0 right-0 bg-white border-b border-olive-200 z-50 shadow-sm">
	          <div class="report-shell">
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
	        <div class="report-shell pt-24 pb-12">
          
          <!-- Hero Section -->
          <div class="card p-8 mb-8 fade-in pdf-page-two">
            <div class="pdf-only pdf-section-label">Executive Summary</div>
            <h1 class="text-4xl font-display font-bold text-olive-900 mb-2 pdf-summary-title">Nmap Port Scanning Results</h1>
            <p class="text-sm text-olive-500 mb-1 pdf-summary-subtitle">
              Techmore Network Scanner <xsl:value-of select="$techmore_version"/>
            </p>
            <p class="text-olive-600 mb-4 pdf-summary-subtitle">
              Version <xsl:value-of select="/nmaprun/@version"/> ·
              <xsl:value-of select="/nmaprun/@startstr"/> – <xsl:value-of select="/nmaprun/runstats/finished/@timestr"/>
            </p>

            <div class="report-network-grid">
              <div>
                <span class="block text-[7px] uppercase tracking-wide text-olive-600">Local IP</span>
                <strong class="block text-[8px] text-olive-900">
                  <xsl:choose>
                    <xsl:when test="string-length(normalize-space($local_ip)) &gt; 0"><xsl:value-of select="$local_ip"/></xsl:when>
                    <xsl:otherwise>Unknown</xsl:otherwise>
                  </xsl:choose>
                </strong>
              </div>
              <div>
                <span class="block text-[7px] uppercase tracking-wide text-olive-600">Subnet Mask</span>
                <strong class="block text-[8px] text-olive-900">
                  <xsl:choose>
                    <xsl:when test="string-length(normalize-space($subnet_mask)) &gt; 0"><xsl:value-of select="$subnet_mask"/></xsl:when>
                    <xsl:otherwise>Unknown</xsl:otherwise>
                  </xsl:choose>
                </strong>
              </div>
              <div>
                <span class="block text-[7px] uppercase tracking-wide text-olive-600">CIDR</span>
                <strong class="block text-[8px] text-olive-900">
                  <xsl:choose>
                    <xsl:when test="string-length(normalize-space($cidr)) &gt; 0"><xsl:value-of select="$cidr"/></xsl:when>
                    <xsl:otherwise>Unknown</xsl:otherwise>
                  </xsl:choose>
                </strong>
              </div>
              <div>
                <span class="block text-[7px] uppercase tracking-wide text-olive-600">Public IP</span>
                <strong class="block text-[8px] text-olive-900">
                  <xsl:choose>
                    <xsl:when test="string-length(normalize-space($public_ip)) &gt; 0"><xsl:value-of select="$public_ip"/></xsl:when>
                    <xsl:otherwise>Unknown</xsl:otherwise>
                  </xsl:choose>
                </strong>
              </div>
            </div>

            <div class="report-traceroute-summary mb-6">
              <span class="block text-[7px] uppercase tracking-wide text-olive-600">Traceroute</span>
              <strong class="block text-[8px] text-olive-900">
                <xsl:choose>
                  <xsl:when test="string-length(normalize-space($traceroute_summary)) &gt; 0"><xsl:value-of select="$traceroute_summary"/></xsl:when>
                  <xsl:otherwise>No traceroute hops were cached when this report was generated.</xsl:otherwise>
                </xsl:choose>
              </strong>
            </div>
            
            <div class="bg-olive-50 border border-olive-200 rounded-lg p-4 mb-6 no-print">
              <pre class="text-xs overflow-x-auto"><a target="_blank" class="text-olive-700 hover:text-olive-900"><xsl:attribute name="href">https://explainshell.com/explain?cmd=<xsl:value-of select="/nmaprun/@args"/></xsl:attribute><xsl:value-of select="/nmaprun/@args"/></a></pre>
            </div>
            
            <div class="grid grid-cols-3 gap-4 mb-6 pdf-card-grid-3">
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-900"><xsl:value-of select="/nmaprun/runstats/hosts/@total"/></div>
                <div class="text-sm text-olive-600">Total IPs Scanned</div>
              </div>
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-600"><xsl:value-of select="/nmaprun/runstats/hosts/@up"/></div>
                <div class="text-sm text-olive-600">Hosts Online</div>
              </div>
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-400"><xsl:value-of select="/nmaprun/runstats/hosts/@down"/></div>
                <div class="text-sm text-olive-600">Hosts Offline</div>
              </div>
            </div>

            <!-- Enhanced Summary Dashboard -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6 pdf-kpi-grid">
              <!-- Critical Vulnerabilities -->
              <div class="card p-4">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-red-100 rounded-full flex items-center justify-center">
                      <span class="text-red-600 font-bold text-sm">!</span>
                    </div>
                  </div>
                  <div class="ml-3">
                    <div id="vuln-critical-total" class="text-2xl font-bold text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &gt;= 9])"/>
                    </div>
                    <div class="text-sm text-olive-600">Critical Vulns (CVSS ≥9.0)</div>
                  </div>
                </div>
              </div>

              <!-- Device Types -->
              <div class="card p-4">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-olive-100 rounded-full flex items-center justify-center">
                      <span class="text-olive-600 font-bold text-sm">🖥️</span>
                    </div>
                  </div>
                  <div class="ml-3">
                    <div class="text-2xl font-bold text-olive-700">
                      <xsl:value-of select="count(/nmaprun/host[os/osmatch/@name])"/>
                    </div>
                    <div class="text-sm text-olive-600">OS Identified</div>
                  </div>
                </div>
              </div>

              <!-- Open Ports -->
              <div class="card p-4">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                      <span class="text-blue-600 font-bold text-sm">🔓</span>
                    </div>
                  </div>
                  <div class="ml-3">
                    <div class="text-2xl font-bold text-blue-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open'])"/>
                    </div>
                    <div class="text-sm text-olive-600">Total Open Ports</div>
                  </div>
                </div>
              </div>

              <!-- Web Services -->
              <div class="card p-4">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                      <span class="text-green-600 font-bold text-sm">🌐</span>
                    </div>
                  </div>
                  <div class="ml-3">
                    <div class="text-2xl font-bold text-green-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and (service/@name='http' or service/@name='https' or service/@tunnel='ssl')])"/>
                    </div>
                    <div class="text-sm text-olive-600">Web Services</div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Network & Vulnerability Summary -->
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

              <!-- Device Vendors -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Top Vendors</h3>
                <div class="space-y-2">
                  <xsl:for-each select="/nmaprun/host/address[@addrtype='mac']/@vendor[not(. = preceding::address/@vendor)]">
                    <xsl:sort select="count(/nmaprun/host[address[@addrtype='mac' and @vendor=current()]])" data-type="number" order="descending"/>
                    <xsl:if test="position() &lt;= 5 and string-length(.) > 0">
                      <div class="flex justify-between items-center">
                        <span class="text-sm text-olive-700 truncate max-w-xs" title="{.}">
                          <xsl:value-of select="substring(., 1, 25)"/>
                          <xsl:if test="string-length(.) > 25">...</xsl:if>
                        </span>
                        <span class="text-sm font-medium text-olive-900 ml-2">
                          <xsl:value-of select="count(/nmaprun/host[address[@addrtype='mac' and @vendor=current()]])"/>
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>
            </div>

            <!-- Security Risk Assessment -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6 pdf-card-grid-2">
              <!-- High-Risk Services -->
              <div class="card p-4 border-l-4 border-red-400">
                <h3 class="text-lg font-semibold text-olive-900 mb-3 flex items-center">
                  <span class="w-3 h-3 bg-red-500 rounded-full mr-2"></span>
                  High-Risk Services
                </h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">SSH Servers</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@name='ssh'])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Remote Desktop</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and (service/@name='rdp' or service/@name='ms-wbt-server')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">SMB/File Shares</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and (service/@name='netbios-ssn' or service/@name='microsoft-ds')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Telnet (Unencrypted)</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@name='telnet'])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">FTP (Unencrypted)</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@name='ftp'])"/>
                    </span>
                  </div>
                </div>
              </div>

              <!-- Compliance & Security Issues -->
              <div class="card p-4 border-l-4 border-orange-400">
                <h3 class="text-lg font-semibold text-olive-900 mb-3 flex items-center">
                  <span class="w-3 h-3 bg-orange-500 rounded-full mr-2"></span>
                  Security Issues
                </h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Default HTTP Ports</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and @portid='80' and service/@name='http' and not(service/@tunnel='ssl')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Hosts with >10 Open Ports</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host[count(ports/port[state/@state='open']) > 10])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Unknown Services</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@name='unknown'])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Outdated SSL/TLS</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[script[@id='ssl-enum-ciphers'] and script/elem[contains(text(), 'SSLv3') or contains(text(), 'TLSv1.0') or contains(text(), 'TLSv1.1')]])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Hosts Without Hostnames</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host[not(hostnames/hostname/@name) or hostnames/hostname/@name=''])"/>
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <!-- Top 10 Most Vulnerable & Most Open Ports -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6 pdf-card-grid-2">
              <!-- Hosts with Vulnerabilities -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Hosts with Vulnerabilities</h3>
                <div class="space-y-2 max-h-64 overflow-y-auto">
                  <xsl:for-each select="/nmaprun/host[ports/port/script[@id='vulners']]">
                    <xsl:if test="position() &lt;= 10">
                      <div class="flex justify-between items-center py-1">
                        <span class="text-sm font-mono text-olive-700">
                          <xsl:value-of select="address/@addr"/>
                        </span>
                        <span class="text-sm font-medium text-red-600 bg-red-50 px-2 py-1 rounded">
                          <xsl:choose>
                            <xsl:when test="ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &gt;= 9]">Critical</xsl:when>
                            <xsl:when test="ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &gt;= 7]">High</xsl:when>
                            <xsl:when test="ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &gt;= 4]">Medium</xsl:when>
                            <xsl:when test="ports/port/script[@id='vulners']//elem[@key='cvss' and number(.) &gt;= 0]">Low</xsl:when>
                            <xsl:otherwise>Unrated</xsl:otherwise>
                          </xsl:choose>
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>

              <!-- Hosts with Most Open Ports -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Most Open Ports</h3>
                <div class="space-y-2 max-h-64 overflow-y-auto">
                  <xsl:for-each select="/nmaprun/host">
                    <xsl:sort select="count(ports/port[state/@state='open'])" data-type="number" order="descending"/>
                    <xsl:if test="position() &lt;= 10 and count(ports/port[state/@state='open']) > 0">
                      <div class="flex justify-between items-center py-1">
                        <span class="text-sm font-mono text-olive-700">
                          <xsl:value-of select="address/@addr"/>
                        </span>
                        <span class="text-sm font-medium text-blue-600 bg-blue-50 px-2 py-1 rounded">
                          <xsl:value-of select="count(ports/port[state/@state='open'])"/> ports
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>
            </div>

            <!-- Network Health & Performance -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6 pdf-card-grid-3">
              <!-- Network Utilization -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Network Utilization</h3>
                <div class="space-y-3">
                  <div>
                    <div class="flex justify-between text-sm mb-1">
                      <span class="text-olive-700">IP Space Used</span>
                      <span class="font-medium text-olive-900">
                        <xsl:value-of select="format-number(/nmaprun/runstats/hosts/@up div /nmaprun/runstats/hosts/@total * 100, '0.1')"/>%
                      </span>
                    </div>
                    <div class="w-full bg-olive-200 rounded-full h-2">
                      <div class="bg-olive-600 h-2 rounded-full">
                        <xsl:attribute name="style">width: <xsl:value-of select="/nmaprun/runstats/hosts/@up div /nmaprun/runstats/hosts/@total * 100"/>%</xsl:attribute>
                      </div>
                    </div>
                  </div>
                  <div class="text-xs text-olive-600">
                    <xsl:value-of select="/nmaprun/runstats/hosts/@up"/> of <xsl:value-of select="/nmaprun/runstats/hosts/@total"/> IPs responding
                  </div>
                </div>
              </div>

              <!-- Scan Performance -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Scan Performance</h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Duration</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="/nmaprun/runstats/finished/@elapsed"/>s
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Avg per Host</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="format-number(/nmaprun/runstats/finished/@elapsed div /nmaprun/runstats/hosts/@total, '0.1')"/>s
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Hosts/sec</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="format-number(/nmaprun/runstats/hosts/@total div /nmaprun/runstats/finished/@elapsed, '0.1')"/>
                    </span>
                  </div>
                </div>
              </div>

              <!-- Data Collection Summary -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Data Collected</h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">OS Fingerprints</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="count(/nmaprun/host[os/osmatch])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Service Versions</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@version])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">MAC Addresses</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="count(/nmaprun/host/address[@addrtype='mac'])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Hosts with Vulners Output</span>
                    <span id="vuln-host-output-count" class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="count(/nmaprun/host[ports/port/script[@id='vulners']])"/>
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <!-- Top Services & OS Summary -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6 pdf-card-grid-2">
              <!-- Top Services -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Top Services</h3>
                <div class="space-y-2">
                  <xsl:for-each select="/nmaprun/host/ports/port[state/@state='open']/service/@name[not(. = preceding::service/@name)]">
                    <xsl:sort select="count(/nmaprun/host/ports/port[state/@state='open']/service[@name=current()])" data-type="number" order="descending"/>
                    <xsl:if test="position() &lt;= 5">
                      <div class="flex justify-between items-center">
                        <span class="text-sm text-olive-700"><xsl:value-of select="."/></span>
                        <span class="text-sm font-medium text-olive-900">
                          <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open']/service[@name=current()])"/>
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>

              <!-- OS Distribution -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">OS Distribution</h3>
                <div class="space-y-2">
                  <xsl:for-each select="/nmaprun/host/os/osmatch/@name[not(. = preceding::osmatch/@name)]">
                    <xsl:sort select="count(/nmaprun/host[os/osmatch/@name=current()])" data-type="number" order="descending"/>
                    <xsl:if test="position() &lt;= 5">
                      <div class="flex justify-between items-center">
                        <span class="text-sm text-olive-700 truncate max-w-xs" title="{.}">
                          <xsl:value-of select="substring(., 1, 30)"/>
                          <xsl:if test="string-length(.) > 30">...</xsl:if>
                        </span>
                        <span class="text-sm font-medium text-olive-900 ml-2">
                          <xsl:value-of select="count(/nmaprun/host[os/osmatch/@name=current()])"/>
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
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
            
            <!-- Keyword Highlighting -->
            <div class="border-t border-olive-200 pt-6 no-print">
              <label class="block text-sm font-medium text-olive-900 mb-2">Highlight Keywords in Services</label>
              <textarea id="keyword-input" rows="2" placeholder="sha1, password, md5, login..." 
                        class="w-full mb-3">sha1,login,password,md5</textarea>
              <div class="flex space-x-3">
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
              <div class="table-scroll">
              <table id="table-overview" class="w-full table-wide">
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
          </div>

          <!-- Open Services -->
          <div id="openservices" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Open Services</h2>
            <div class="card p-6">
              <div class="table-scroll">
              <table id="table-services" class="w-full text-sm table-wide">
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
	          </div>

	          <!-- Web Services -->
	          <div id="webservices" class="mb-12 fade-in">
	            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Web Services</h2>
	            <div class="card p-6">
	              <div class="table-scroll">
	              <table id="web-services" class="w-full text-sm table-wide">
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
	          </div>

          <!-- Product Versions -->
	          <div id="productversions" class="mb-12 fade-in">
	            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Product Versions</h2>
	            <div class="card p-6">
	              <div class="table-scroll">
	              <table id="table-product-versions" class="w-full text-sm table-wide">
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
	          </div>

          <!-- SSH Authentication -->
          <xsl:if test="count(/nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']) &gt; 0">
            <div id="ssh-auth" class="mb-12 fade-in">
	              <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">SSH Authentication</h2>
	              <div class="card p-6">
	                <div class="table-scroll">
	                <table id="table-ssh-auth" class="w-full text-sm table-wide">
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
                                      <pre class="text-xs bg-white p-3 rounded border border-olive-200 overflow-x-auto"><xsl:value-of select="@output"/></pre>
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
          <div class="report-shell text-center text-sm text-olive-600">
          <!--
            <p class="mb-2">
              Report generated by <a href="https://pentestfactory.com" class="text-olive-700 hover:text-olive-900">Pentest Factory GmbH</a>
            </p>
            <p class="mb-4">
              Questions or problems? <a href="mailto:team@pentestfactory.de" class="text-olive-700 hover:text-olive-900">Contact us</a>
            </p>
            <p class="text-xs">
              ❤️ Original Bootstrap template by <a href="https://github.com/honze-net/nmap-bootstrap-xsl" target="_blank" class="text-olive-700">Andreas Hontzia</a> ·
              Tweaks by <a href="https://github.com/l4rm4nd" target="_blank" class="text-olive-700">LRVT</a> ·
              Modern design update 2026 ·
              Techmore Network Scanner <xsl:value-of select="$techmore_version"/>
            </p>
            -->
          </div>
        </footer>

        <section class="end-of-report-page">
          End Of Report
        </section>

        <script id="nmapui-report-runtime">__NMAPUI_REPORT_RUNTIME__</script>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
