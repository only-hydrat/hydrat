package org.hydrat.app

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.graphics.drawable.StateListDrawable
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

internal class DashboardStyle(private val context: Context) {
    fun dp(value: Int) = (value * context.resources.displayMetrics.density).toInt()
    fun block(top: Int) = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(top) }
    fun column() = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }

    fun shape(color: Int, radius: Int) = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(radius).toFloat()
    }

    fun divider() = android.view.View(context).apply { setBackgroundColor(DIVIDER) }

    fun card() = column().apply {
        background = shape(SURFACE, 18)
        setPadding(dp(16), dp(15), dp(16), dp(15))
    }

    fun text(value: String, size: Int, muted: Boolean = false, bold: Boolean = false) =
        TextView(context).apply {
            text = value
            textSize = size.toFloat()
            setTextColor(if (muted) MUTED else TEXT)
            if (bold) typeface = Typeface.create("sans-serif", Typeface.BOLD)
            setLineSpacing(dp(2).toFloat(), 1f)
        }

    fun heading(value: String) = text(value, 19, bold = true).apply { setAccessibilityHeading(true) }

    fun button(value: String, primary: Boolean = true, action: () -> Unit) =
        Button(context).apply {
            text = value
            isAllCaps = false
            textSize = 15f
            minHeight = dp(48)
            minimumHeight = dp(48)
            minimumWidth = 0
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(8), dp(8), dp(8))
            stateListAnimator = null
            styleButton(this, primary)
            setOnClickListener { action() }
        }

    fun styleButton(button: Button, primary: Boolean, selected: Boolean = false) {
        val bg = when {
            primary -> ACCENT
            selected -> SELECTED
            else -> BACKGROUND
        }
        val fg = if (primary) INK else if (selected) ACCENT else TEXT
        val states = StateListDrawable().apply {
            addState(intArrayOf(android.R.attr.state_focused), shape(bg, 13).apply {
                setStroke(dp(2), if (primary) INK else ACCENT)
            })
            addState(intArrayOf(), shape(bg, 13))
        }
        button.background = RippleDrawable(ColorStateList.valueOf(0x2577DAB2), states, null)
        button.setTextColor(ColorStateList(
            arrayOf(intArrayOf(-android.R.attr.state_enabled), intArrayOf()),
            intArrayOf(if (primary) 0xFF32644E.toInt() else 0xFF81928A.toInt(), fg)
        ))
    }

    companion object {
        val BACKGROUND = Color.rgb(14, 24, 20)
        val SURFACE = Color.rgb(24, 39, 33)
        val DIVIDER = Color.rgb(47, 66, 57)
        val SELECTED = Color.rgb(35, 61, 49)
        val TEXT = Color.rgb(231, 242, 235)
        val MUTED = Color.rgb(172, 195, 181)
        val ACCENT = Color.rgb(139, 226, 184)
        val INK = Color.rgb(14, 42, 29)
    }
}
