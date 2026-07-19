package com.anatdx.yukisu.ui.component

import android.annotation.SuppressLint
import androidx.compose.animation.*
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import com.anatdx.yukisu.ui.theme.isExpressiveUi

@SuppressLint("AutoboxingStateCreation")
@Composable
fun rememberFabVisibilityState(listState: LazyListState): State<Boolean> {
    var previousScrollOffset by remember { mutableStateOf(0) }
    var previousIndex by remember { mutableStateOf(0) }
    val fabVisible = remember { mutableStateOf(true) }

    LaunchedEffect(listState) {
        snapshotFlow { listState.firstVisibleItemIndex to listState.firstVisibleItemScrollOffset }
            .collect { (index, offset) ->
                if (previousIndex == 0 && previousScrollOffset == 0) {
                    fabVisible.value = true
                } else {
                    val isScrollingDown = when {
                        index > previousIndex -> false
                        index < previousIndex -> true
                        else -> offset < previousScrollOffset
                    }

                    fabVisible.value = isScrollingDown
                }

                previousIndex = index
                previousScrollOffset = offset
            }
    }

    return fabVisible
}

@Composable
fun AnimatedFab(
    visible: Boolean,
    content: @Composable () -> Unit
) {
    if (!isExpressiveUi) {
        val scale by animateFloatAsState(
            targetValue = if (visible) 1f else 0f,
            animationSpec = spring(
                dampingRatio = Spring.DampingRatioMediumBouncy,
                stiffness = Spring.StiffnessLow
            ),
            label = "ClassicFabScale",
        )

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn() + scaleIn(),
            exit = fadeOut() + scaleOut(targetScale = 0.8f)
        ) {
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(16.dp))
                    .scale(scale)
                    .alpha(scale)
            ) {
                content()
            }
        }
        return
    }

    val hiddenOffsetPx = with(LocalDensity.current) { 28.dp.toPx() }
    AnimatedVisibility(
        visible = visible,
        enter = EnterTransition.None,
        exit = ExitTransition.None,
    ) {
        val animatedScale by transition.animateFloat(
            transitionSpec = {
                if (targetState == EnterExitState.Visible) {
                    spring(
                        dampingRatio = Spring.DampingRatioMediumBouncy,
                        stiffness = Spring.StiffnessLow,
                    )
                } else {
                    spring(
                        dampingRatio = Spring.DampingRatioNoBouncy,
                        stiffness = Spring.StiffnessMediumLow,
                        visibilityThreshold = 0.025f,
                    )
                }
            },
            label = "ExpressiveFabScale",
        ) { state ->
            if (state == EnterExitState.Visible) 1f else 0f
        }
        val visualScale = animatedScale.coerceIn(0f, 1.08f)

        Box(
            modifier = Modifier.graphicsLayer {
                scaleX = visualScale
                scaleY = visualScale
                translationY = (1f - visualScale.coerceAtMost(1f)) * hiddenOffsetPx
                clip = false
            }
        ) {
            content()
        }
    }
}
