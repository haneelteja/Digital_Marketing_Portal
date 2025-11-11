const fs = require('fs');
const path = require('path');
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableCell, TableRow, AlignmentType, BorderStyle, WidthType } = require('docx');

// Get input file from command line or use default
const inputFile = process.argv[2] || 'BUSINESS_REQUIREMENTS_DOCUMENT.md';
const outputFile = process.argv[3] || inputFile.replace('.md', '.docx');

// Read the markdown file
const markdownPath = path.join(__dirname, '..', inputFile);
if (!fs.existsSync(markdownPath)) {
  console.error(`❌ Error: File not found: ${inputFile}`);
  process.exit(1);
}
const markdownContent = fs.readFileSync(markdownPath, 'utf-8');

// Parse markdown and convert to DOCX elements
const lines = markdownContent.split('\n');
const docElements = [];
let currentTableRows = [];
let inTable = false;
let tableHeaders = [];

// Helper function to process text with formatting
function processText(line) {
  const parts = [];
  let currentIndex = 0;
  
  // Handle bold text **text**
  const boldRegex = /\*\*(.*?)\*\*/g;
  let match;
  
  while ((match = boldRegex.exec(line)) !== null) {
    if (match.index > currentIndex) {
      parts.push(new TextRun(line.substring(currentIndex, match.index)));
    }
    parts.push(new TextRun({ text: match[1], bold: true }));
    currentIndex = match.index + match[0].length;
  }
  
  if (currentIndex < line.length) {
    parts.push(new TextRun(line.substring(currentIndex)));
  }
  
  return parts.length > 0 ? parts : [new TextRun(line)];
}

for (let i = 0; i < lines.length; i++) {
  let line = lines[i];
  const originalLine = line;
  const trimmedLine = line.trim();
  
  // Skip code blocks
  if (trimmedLine.startsWith('```')) {
    continue;
  }
  
  // Skip horizontal rules
  if (trimmedLine.match(/^[-*]{3,}$/) || trimmedLine === '---') {
    continue;
  }
  
  // Handle headers
  if (trimmedLine.startsWith('# ')) {
    if (inTable && (currentTableRows.length > 0 || tableHeaders.length > 0)) {
      const tableBody = tableHeaders.length > 0 
        ? [new TableRow({ 
            children: tableHeaders.map(h => new TableCell({ 
              children: [new Paragraph({ text: h, bold: true })] 
            }))
          }), ...currentTableRows]
        : currentTableRows;
      docElements.push(new Table({ rows: tableBody, width: { size: 100, type: WidthType.PERCENTAGE } }));
      currentTableRows = [];
      tableHeaders = [];
      inTable = false;
    }
    docElements.push(new Paragraph({ text: trimmedLine.substring(2), heading: HeadingLevel.HEADING_1 }));
    continue;
  }
  
  if (trimmedLine.startsWith('## ')) {
    if (inTable && (currentTableRows.length > 0 || tableHeaders.length > 0)) {
      const tableBody = tableHeaders.length > 0 
        ? [new TableRow({ 
            children: tableHeaders.map(h => new TableCell({ 
              children: [new Paragraph({ text: h, bold: true })] 
            }))
          }), ...currentTableRows]
        : currentTableRows;
      docElements.push(new Table({ rows: tableBody, width: { size: 100, type: WidthType.PERCENTAGE } }));
      currentTableRows = [];
      tableHeaders = [];
      inTable = false;
    }
    docElements.push(new Paragraph({ text: trimmedLine.substring(3), heading: HeadingLevel.HEADING_2 }));
    continue;
  }
  
  if (trimmedLine.startsWith('### ')) {
    if (inTable && (currentTableRows.length > 0 || tableHeaders.length > 0)) {
      const tableBody = tableHeaders.length > 0 
        ? [new TableRow({ 
            children: tableHeaders.map(h => new TableCell({ 
              children: [new Paragraph({ text: h, bold: true })] 
            }))
          }), ...currentTableRows]
        : currentTableRows;
      docElements.push(new Table({ rows: tableBody, width: { size: 100, type: WidthType.PERCENTAGE } }));
      currentTableRows = [];
      tableHeaders = [];
      inTable = false;
    }
    docElements.push(new Paragraph({ text: trimmedLine.substring(4), heading: HeadingLevel.HEADING_3 }));
    continue;
  }
  
  if (trimmedLine.startsWith('#### ')) {
    if (inTable && (currentTableRows.length > 0 || tableHeaders.length > 0)) {
      const tableBody = tableHeaders.length > 0 
        ? [new TableRow({ 
            children: tableHeaders.map(h => new TableCell({ 
              children: [new Paragraph({ text: h, bold: true })] 
            }))
          }), ...currentTableRows]
        : currentTableRows;
      docElements.push(new Table({ rows: tableBody, width: { size: 100, type: WidthType.PERCENTAGE } }));
      currentTableRows = [];
      tableHeaders = [];
      inTable = false;
    }
    docElements.push(new Paragraph({ text: trimmedLine.substring(5), heading: HeadingLevel.HEADING_4 }));
    continue;
  }

  // Handle tables
  if (trimmedLine.includes('|') && trimmedLine.split('|').length > 2) {
    if (!inTable) {
      inTable = true;
    }
    const cells = trimmedLine.split('|').map(c => c.trim()).filter(c => c && c !== '');
    
    if (cells.length > 0) {
      // Skip separator rows (|---|---|)
      if (cells.every(c => /^[-:\s|]+$/.test(c))) {
        continue;
      }
      // First row is headers
      if (tableHeaders.length === 0) {
        tableHeaders = cells;
      } else {
        currentTableRows.push(
          new TableRow({
            children: cells.map(cell => {
              const textParts = processText(cell);
              return new TableCell({ 
                children: [new Paragraph({ children: textParts })] 
              });
            })
          })
        );
      }
    }
    continue;
  } else if (inTable) {
    // End table if we hit a non-table line
    if (currentTableRows.length > 0 || tableHeaders.length > 0) {
      const tableBody = tableHeaders.length > 0 
        ? [new TableRow({ 
            children: tableHeaders.map(h => new TableCell({ 
              children: [new Paragraph({ text: h, bold: true })] 
            }))
          }), ...currentTableRows]
        : currentTableRows;
      docElements.push(new Table({ rows: tableBody, width: { size: 100, type: WidthType.PERCENTAGE } }));
      currentTableRows = [];
      tableHeaders = [];
      inTable = false;
    }
  }

  // Handle lists
  if (trimmedLine.match(/^[-*]\s/) || trimmedLine.match(/^\d+\.\s/)) {
    const listItem = trimmedLine.replace(/^[-*]\s/, '').replace(/^\d+\.\s/, '');
    const textParts = processText(listItem);
    docElements.push(new Paragraph({ 
      children: textParts,
      bullet: { level: 0 }
    }));
    continue;
  }

  // Handle regular paragraphs with formatting
  if (trimmedLine) {
    const textParts = processText(trimmedLine);
    if (textParts.length === 1 && textParts[0].text === trimmedLine) {
      // Simple text, no formatting
      docElements.push(new Paragraph({ text: trimmedLine }));
    } else {
      // Has formatting
      docElements.push(new Paragraph({ children: textParts }));
    }
  } else {
    // Empty line
    docElements.push(new Paragraph({ text: '' }));
  }
}

// Handle remaining table
if (inTable && (currentTableRows.length > 0 || tableHeaders.length > 0)) {
  const tableBody = tableHeaders.length > 0 
    ? [new TableRow({ 
        children: tableHeaders.map(h => new TableCell({ 
          children: [new Paragraph({ text: h, bold: true })] 
        }))
      }), ...currentTableRows]
    : currentTableRows;
  docElements.push(new Table({ rows: tableBody, width: { size: 100, type: WidthType.PERCENTAGE } }));
}

// Create the document
const doc = new Document({
  sections: [{
    properties: {},
    children: docElements,
  }],
});

// Generate and save the DOCX file
const outputPath = path.join(__dirname, '..', outputFile);
Packer.toBuffer(doc).then((buffer) => {
  fs.writeFileSync(outputPath, buffer);
  console.log(`✅ Successfully converted ${inputFile} to ${outputFile}`);
  console.log(`📄 Output file: ${outputPath}`);
}).catch((error) => {
  console.error('❌ Error converting to DOCX:', error);
  process.exit(1);
});
