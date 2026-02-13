"""
Telescan - Telegram Bot for Website and File Virus Scanning
Main application entry point
"""

import os
import sys
# Add current directory to path for imports
sys.path.insert(0, os.getcwd())

import logging
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, CallbackQueryHandler, CallbackContext

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

from config import BOT_TOKEN, MAX_FILE_SIZE
from scanners.file_scanner import FileScanner
from scanners.website_scanner import WebsiteScanner
from utils.helpers import format_scan_result, get_file_info
from utils.stats import stats_tracker

# Initialize scanners
file_scanner = FileScanner()
website_scanner = WebsiteScanner()

# Main menu keyboard
MAIN_KEYBOARD = [
    [KeyboardButton("📁 Scan File")],
    [KeyboardButton("🌐 Scan Website")],
    [KeyboardButton("📊 Status")],
    [KeyboardButton("🔍 Help")]
]

# Inline keyboard for scan options
SCAN_OPTIONS_KEYBOARD = [
    [
        InlineKeyboardButton("📁 Send File", callback_data="scan_file"),
        InlineKeyboardButton("🌐 Enter URL", callback_data="scan_url")
    ],
    [
        InlineKeyboardButton("📊 Status", callback_data="status"),
        InlineKeyboardButton("🔍 Help", callback_data="help")
    ]
]

def get_main_keyboard():
    """Get the main menu keyboard"""
    return ReplyKeyboardMarkup(MAIN_KEYBOARD, resize_keyboard=True, one_time_keyboard=False)

def get_inline_keyboard():
    """Get inline keyboard for messages"""
    return InlineKeyboardMarkup(SCAN_OPTIONS_KEYBOARD)

async def start(update: Update, context: CallbackContext):
    """Handle /start command"""
    welcome_message = """
🛡️ *Welcome to Telescan Bot* 🛡️

I'm your security companion for scanning websites and files for malicious content.

*What I can do:*
🔍 Scan files for viruses and malware
🌐 Analyze websites for threats
📊 Check suspicious URLs

*How to use:*
Simply tap a button below or use commands:
/scan_file - Send a file to scan
/scan_url [website_url] - Scan a website

Let's keep the internet safe together! 🔒
    """
    
    await update.message.reply_text(
        welcome_message, 
        parse_mode='Markdown',
        reply_markup=get_main_keyboard()
    )

async def help_command(update: Update, context: CallbackContext):
    """Handle /help command"""
    help_message = """
🔍 *Telescan Help* 🔍

*Buttons:*
📁 Scan File - Send any file for virus scanning
🌐 Scan Website - Enter a URL to analyze
📊 Status - Check scanner status
🔍 Help - Show this help message

*Commands:*
/start - Start the bot
/help - Show this help message
/scan_file - Upload a file to scan
/scan_url [url] - Scan a website URL
/status - Check scanner status

*Security Tips:*
⚠️ Always scan unknown files before opening
⚠️ Check URLs before visiting suspicious links
⚠️ Keep your antivirus updated

*Supported Files:*
📄 Documents, 📊 Spreadsheets, 💻 Code
🖼️ Images, 📦 Archives, 📱 Applications
    """
    
    await update.message.reply_text(
        help_message, 
        parse_mode='Markdown',
        reply_markup=get_main_keyboard()
    )

async def status_command(update: Update, context: CallbackContext):
    """Check scanner status"""
    status = file_scanner.get_status()
    stats = stats_tracker.get_stats()
    
    status_message = f"""
📊 *Scanner Status*

*📈 Statistics:*
📁 Files Scanned: {stats['files_scanned']}
🌐 URLs Scanned: {stats['urls_scanned']}
🚨 Threats Detected: {stats['threats_detected']}
✅ Clean Files: {stats['clean_files']}
✅ Clean URLs: {stats['clean_urls']}

*🛡️ Scanners:*
✅ File Scanner: Active
✅ Website Scanner: Active
🔧 Engine: {status['engine']}

*📅 Activity:*
🕐 Bot Started: {stats['start_date']}
🕑 Last Scan: {stats['last_scan'] or 'Never'}

*⚙️ System:*
🐍 Python: {status['python_version']}
📦 Max File Size: {MAX_FILE_SIZE // (1024*1024)}MB
"""
    
    await update.message.reply_text(
        status_message, 
        parse_mode='Markdown',
        reply_markup=get_main_keyboard()
    )

async def handle_text_buttons(update: Update, context: CallbackContext):
    """Handle text button presses and URLs"""
    text = update.message.text
    
    # Check if it's a URL
    if text.startswith('http://') or text.startswith('https://'):
        await scan_url_text(update, context)
        return
    
    if text == "📁 Scan File":
        await update.message.reply_text(
            "📁 *Send me a file to scan*\n\nYou can:\n• Attach a file directly\n• Forward a file from another chat\n• Share a document\n\nSupported types: Documents, Images, Archives, Code files",
            parse_mode='Markdown',
            reply_markup=get_main_keyboard()
        )
    
    elif text == "🌐 Scan Website":
        await update.message.reply_text(
            "🌐 *Send me a website URL to scan*\n\nJust send the URL like:\n`https://example.com`\n\nI'll analyze it for:\n• Phishing indicators\n• Malware links\n• Suspicious content\n• SSL security",
            parse_mode='Markdown',
            reply_markup=get_main_keyboard()
        )
    
    elif text == "📊 Status":
        await status_command(update, context)
    
    elif text == "🔍 Help":
        await help_command(update, context)


async def scan_url_text(update: Update, context: CallbackContext):
    """Handle URL messages (not commands)"""
    url = update.message.text
    await update.message.reply_text(f"🔍 Scanning website: {url}... 🛡️")
    
    try:
        result = await website_scanner.scan_website(url)
        result_message = format_scan_result("website", {"url": url}, result)
        
        # Update statistics
        is_clean = result.get("clean", True) and not result.get("threats")
        stats_tracker.increment_urls_scanned(clean=is_clean)
        
        # Add action buttons
        keyboard = [
            [InlineKeyboardButton("🔄 Scan Another URL", callback_data="scan_url")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            result_message, 
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
        
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        await update.message.reply_text(
            f"❌ Error scanning URL: {str(e)}",
            reply_markup=get_main_keyboard()
        )

async def handle_file(update: Update, context: CallbackContext):
    """Handle file uploads"""
    document = update.message.document
    
    if document.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(
            f"❌ File too large! Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB",
            reply_markup=get_main_keyboard()
        )
        return
    
    await update.message.reply_text("📁 Processing file... ⏳")
    
    try:
        # Download file
        file_path = await document.get_file()
        temp_file = f"temp_{document.file_id}_{document.file_name}"
        await file_path.download_to_drive(temp_file)
        
        # Get file info
        file_info = get_file_info(temp_file)
        
        # Scan file
        await update.message.reply_text("🔍 Scanning file for threats... 🛡️")
        result = await file_scanner.scan_file(temp_file)
        
        # Format and send result
        result_message = format_scan_result("file", file_info, result)
        
        # Update statistics
        is_clean = result.get("clean", True) and not result.get("threats")
        stats_tracker.increment_files_scanned(clean=is_clean)
        
        # Add action buttons
        keyboard = [
            [InlineKeyboardButton("🔄 Scan Another File", callback_data="scan_file")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            result_message, 
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
        
        # Clean up
        if os.path.exists(temp_file):
            os.remove(temp_file)
            
    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        await update.message.reply_text(
            f"❌ Error scanning file: {str(e)}",
            reply_markup=get_main_keyboard()
        )
        # Clean up on error
        if 'temp_file' in locals() and os.path.exists(temp_file):
            os.remove(temp_file)

async def scan_url_command(update: Update, context: CallbackContext):
    """Handle /scan_url command"""
    if not context.args:
        await update.message.reply_text(
            "🌐 *Send me a website URL to scan*\n\nJust send the URL like:\n`https://example.com`",
            parse_mode='Markdown',
            reply_markup=get_main_keyboard()
        )
        return
    
    url = context.args[0]
    await update.message.reply_text(f"🔍 Scanning website: {url}... 🛡️")
    
    try:
        result = await website_scanner.scan_website(url)
        result_message = format_scan_result("website", {"url": url}, result)
        
        # Update statistics
        is_clean = result.get("clean", True) and not result.get("threats")
        stats_tracker.increment_urls_scanned(clean=is_clean)
        
        # Add action buttons
        keyboard = [
            [InlineKeyboardButton("🔄 Scan Another URL", callback_data="scan_url")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            result_message, 
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
        
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        await update.message.reply_text(
            f"❌ Error scanning URL: {str(e)}",
            reply_markup=get_main_keyboard()
        )

async def handle_callback(update: Update, context: CallbackContext):
    """Handle inline button callbacks"""
    query = update.callback_query
    await query.answer()
    
    data = query.data
    
    if data == "scan_file":
        await query.edit_message_text(
            "📁 *Send me a file to scan*\n\nYou can:\n• Attach a file directly\n• Forward a file from another chat\n• Share a document\n\nI'll scan it for viruses and malicious content.",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
            ])
        )
    
    elif data == "scan_url":
        await query.edit_message_text(
            "🌐 *Send me a website URL to scan*\n\nJust send the URL like:\n`https://example.com`\n\nI'll analyze it for threats and suspicious content.",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
            ])
        )
    
    elif data == "status":
        status = file_scanner.get_status()
        status_message = f"""
📊 *Scanner Status*

*File Scanner:*
✅ Status: Active
🔧 Engine: {status['engine']}
📝 Signatures: {status['signatures']:,}

*Website Scanner:*
✅ Status: Active
        """
        await query.edit_message_text(
            status_message,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
            ])
        )
    
    elif data == "help":
        help_message = """
🔍 *Telescan Help*

*Buttons:*
📁 Scan File - Send a file for scanning
🌐 Scan Website - Send a URL to analyze
📊 Status - Check scanner status
🔍 Help - Show this help

*Commands:*
/start - Start the bot
/help - Help message
/scan_file - Upload a file
/scan_url [url] - Scan a website

*Supported Files:*
Documents, Images, Archives, Code, Executables
        """
        await query.edit_message_text(
            help_message,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
            ])
        )
    
    elif data == "main_menu":
        await query.edit_message_text(
            "🏠 *Main Menu*\n\nChoose an action:",
            parse_mode='Markdown',
            reply_markup=get_inline_keyboard()
        )

async def error_handler(update: Update, context: CallbackContext):
    """Handle errors"""
    logger.error(f"Update {update} caused error {context.error}")
    if update.message:
        await update.message.reply_text(
            "⚠️ An error occurred. Please try again.",
            reply_markup=get_main_keyboard()
        )

async def main():
    """Main application entry point"""
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN not found in environment variables!")
        return
    
    application = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .concurrent_updates(True)
        .build()
    )
    
    # Initialize the application
    await application.initialize()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("scan_url", scan_url_command))
    
    # Handle text messages (buttons and URLs)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_buttons))
    
    # Handle file uploads
    application.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    
    # Handle callback queries (inline buttons)
    application.add_handler(CallbackQueryHandler(handle_callback))
    
    # Error handler
    application.add_error_handler(error_handler)
    
    # Start the bot
    logger.info("Starting Telescan Bot...")
    await application.start()
    await application.updater.start_polling()
    
    # Keep the bot running
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        await application.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot stopped by user")
